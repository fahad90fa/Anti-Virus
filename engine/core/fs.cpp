#include "sentinel/core/fs.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>

#include "sentinel/core/sha256.h"

namespace fs = std::filesystem;

namespace sentinel {

Result<Bytes> ReadFile(const std::string& path, std::size_t max_bytes) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return Status::Error(ErrorCode::IoError, "cannot open: " + path);
    Bytes data;
    constexpr std::size_t kChunk = 64 * 1024;
    std::vector<char> buf(kChunk);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        const std::size_t to_copy =
            (max_bytes == 0) ? static_cast<std::size_t>(got)
                             : std::min(static_cast<std::size_t>(got), max_bytes - data.size());
        data.insert(data.end(), buf.begin(), buf.begin() + to_copy);
        if (max_bytes != 0 && data.size() >= max_bytes) break;
    }
    return data;
}

Result<std::string> HashFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return Status::Error(ErrorCode::IoError, "cannot open: " + path);
    Sha256 h;
    std::vector<char> buf(64 * 1024);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            h.Update(reinterpret_cast<const std::uint8_t*>(buf.data()),
                     static_cast<std::size_t>(got));
        }
    }
    return Sha256::ToHex(h.Final());
}

Result<std::uint64_t> FileSize(const std::string& path) {
    std::error_code ec;
    const auto sz = fs::file_size(path, ec);
    if (ec) return Status::Error(ErrorCode::IoError, "stat failed: " + path);
    return static_cast<std::uint64_t>(sz);
}

bool PathExists(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec);
}

bool IsRegularFile(const std::string& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

bool IsDirectory(const std::string& path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

bool MakeDirs(const std::string& path) {
    std::error_code ec;
    if (fs::exists(path, ec)) return fs::is_directory(path, ec);
    return fs::create_directories(path, ec);
}

Status WalkFiles(const std::string& root, bool recursive,
                 const std::function<void(const std::string&)>& visit) {
    std::error_code ec;
    if (!fs::exists(root, ec)) {
        return Status::Error(ErrorCode::NotFound, "no such path: " + root);
    }
    if (fs::is_regular_file(root, ec)) {
        visit(root);
        return Status::Ok();
    }
    if (recursive) {
        for (auto it = fs::recursive_directory_iterator(
                 root, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (it->is_regular_file(ec)) visit(it->path().string());
        }
    } else {
        for (auto it = fs::directory_iterator(
                 root, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (it->is_regular_file(ec)) visit(it->path().string());
        }
    }
    return Status::Ok();
}

Status WriteFileAtomic(const std::string& path, const Bytes& data) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return Status::Error(ErrorCode::IoError, "cannot write: " + tmp);
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        if (!out) return Status::Error(ErrorCode::IoError, "write failed: " + tmp);
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        // Fall back to copy+remove across filesystems.
        fs::copy_file(tmp, path, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmp, ec);
        if (ec) return Status::Error(ErrorCode::IoError, "rename failed: " + path);
    }
    return Status::Ok();
}

Status WriteFileAtomic(const std::string& path, const std::string& data) {
    Bytes b(data.begin(), data.end());
    return WriteFileAtomic(path, b);
}

std::string FileName(const std::string& path) {
    return fs::path(path).filename().string();
}

std::string Extension(const std::string& path) {
    std::string ext = fs::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext;
}

std::string ParentDir(const std::string& path) {
    return fs::path(path).parent_path().string();
}

std::string JoinPath(const std::string& a, const std::string& b) {
    return (fs::path(a) / b).string();
}

}  // namespace sentinel
