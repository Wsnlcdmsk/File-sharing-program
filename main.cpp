#include <netinet/in.h>
#include <iostream>
#include <iomanip>
#include "/usr/include/samba-4.0/libsmbclient.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <talloc.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <vector>
#include <algorithm>

#define NOT_IMPLEMENTED 3221225659
#define NT_STATUS_BROKEN_PIPE 3221225803
#define BROKEN_PIPE 32

using namespace std;

const int BUFFER_SIZE = 4096;

int debuglevel = 0;
const char *workgroup = "your_data"; // Замените на вашу рабочую группу
const char *username = "your_data"; // Замените на ваше имя пользователя
const char *password = "your_data"; // Замените на ваш пароль

bool supportsPolicy = true;

TALLOC_CTX *talloc_tos(void);

void printError(int err, string path, string msg)
{
    cerr << "ERROR: " << msg;
    if (!path.empty())
    {
        cerr << " Path:" << path;
    }
    if (errno != 0)
    {
        cerr << " Error Number: " << err << " : " << strerror(err);
    }
    cerr << endl;
}

void delete_smbctx(SMBCCTX* ctx)
{
    smbc_purge_cached_fn fn = smbc_getFunctionPurgeCachedServers(ctx);
    if (fn)
        fn(ctx);
    smbc_free_context(ctx, 1);
}

void printErrorAndExit(int err, string path, string msg, SMBCCTX* ctx)
{
    printError(err, path, msg);
    if (ctx != NULL)
    {
        delete_smbctx(ctx);
    }
    exit(err);
}

void smbc_auth_fn(
    const char *server,
    const char *share,
    char *wrkgrp, int wrkgrplen,
    char *user, int userlen,
    char *passwd, int passwdlen)
{
    (void)server;
    (void)share;
    (void)wrkgrp;
    (void)wrkgrplen;

    strncpy(wrkgrp, workgroup, wrkgrplen - 1); wrkgrp[wrkgrplen - 1] = 0;
    strncpy(user, username, userlen - 1); user[userlen - 1] = 0;
    strncpy(passwd, password, passwdlen - 1); passwd[passwdlen - 1] = 0;
}

SMBCCTX* create_smbctx()
{
    SMBCCTX *ctx;
    int err = smbc_init(smbc_auth_fn, debuglevel);
    if (err != 0)
    {
        printErrorAndExit(err, "", "Could not initialize smbclient library.", NULL);
    }
    ctx = smbc_set_context(NULL);

    smbc_setDebug(ctx, debuglevel);
    smbc_setOptionFullTimeNames(ctx, 1);
    smbc_setOptionNoAutoAnonymousLogin(ctx, 0);
    smbc_setOptionUrlEncodeReaddirEntries(ctx, 1);
    smbc_setOptionSmbEncryptionLevel(ctx, SMBC_ENCRYPTLEVEL_NONE);
    smbc_setOptionOneSharePerServer(ctx, 0);
    smbc_setOptionUseCCache(ctx, 1);

    return ctx;
}

void enumerate(ostream& out, SMBCCTX *ctx, bool recursive, bool children, string path)
{
    TALLOC_CTX *frame = talloc_new(NULL);

    SMBCFILE *fd;
    struct smbc_dirent *dirent;

    int retry = 0;
    do
    {
        retry++;
        fd = smbc_getFunctionOpendir(ctx)(ctx, path.c_str());
    }
    while (errno == BROKEN_PIPE && retry < 5);

    if (fd == NULL)
    {
        printError(errno, path, "Could not open path to enumerate.");
    }
    else
    {
        std::vector<string> childrenToEnumerate;

        while ((dirent = smbc_getFunctionReaddir(ctx)(ctx, fd)) != NULL)
        {
            string name = dirent->name;
            int type = dirent->smbc_type;

            if (name.empty() || name == "." || name == "..")
                continue;

            string fullPath = path + "/" + name;

            // Структура для хранения информации об элементе
            struct FileInfo {
                string url;
                string name;
                int type;
                off_t size;
                time_t lastmod;
                mode_t mode;
            };

            FileInfo fileInfo;
            fileInfo.url = fullPath;
            fileInfo.name = name;
            fileInfo.type = type;

            if (type != SMBC_FILE_SHARE)
            {
                struct stat st;
                if (smbc_stat(fullPath.c_str(), &st) < 0)
                {
                    printError(errno, fullPath, "Could not get attributes of path.");
                }
                else
                {
                    fileInfo.size = st.st_size;
                    fileInfo.lastmod = st.st_mtime;
                    fileInfo.mode = st.st_mode;
                }
            }

            out << "====================" << endl;
            out << "URL: " << fileInfo.url << endl;
            out << "Name: " << fileInfo.name << endl;
            out << "Type: " << fileInfo.type << endl;
            if (fileInfo.type != SMBC_FILE_SHARE)
            {
                out << "Size: " << fileInfo.size << " bytes" << endl;
                out << "Last Modified: " << ctime(&fileInfo.lastmod);
                out << "Mode: " << oct << fileInfo.mode << dec << endl;
            }
            out << "====================" << endl;

            if (recursive && type != SMBC_FILE && children)
            {
                childrenToEnumerate.push_back(fullPath);
            }
        }

        if (fd)
        {
            smbc_getFunctionClose(ctx)(ctx, fd);
        }

        for (auto subPath : childrenToEnumerate)
        {
            enumerate(out, ctx, recursive, true, subPath);
        }
    }

    talloc_free(frame);
}


void read(string path, SMBCCTX *ctx)
{
    char buffer[BUFFER_SIZE];
    int fd;
    long ret;
    int savedErrno;
    struct stat st;

    if ((fd = smbc_open(path.c_str(), O_RDONLY, 0)) < 0)
    {
        printErrorAndExit(errno, path, "Could not open file for reading.", ctx);
    }
    else
    {
        if (smbc_fstat(fd, &st) < 0)
        {
            printError(errno, path, "Could not get attributes of path.");
        }
        else
        {
            cout << "size: " << st.st_size << endl;
            int bytes = 0;

            do
            {
                ret = smbc_read(fd, buffer, BUFFER_SIZE);
                savedErrno = errno;
                if (ret > 0)
                {
                    fwrite(buffer, 1, ret, stdout);
                    fflush(stdout);
                    bytes += ret;
                }

            } while (ret > 0);

            smbc_close(fd);

            if (ret < 0)
            {
                errno = savedErrno;
                printErrorAndExit(savedErrno, path, "Error reading file.", ctx);
            }
        }
    }
}

void write(string path, SMBCCTX *ctx)
{
    char buffer[BUFFER_SIZE];
    int fd;
    long ret;
    int savedErrno;

    if ((fd = smbc_open(path.c_str(), O_WRONLY | O_TRUNC, 0644)) < 0)
    {
        printErrorAndExit(errno, path, "Could not open file for writing.", ctx);
    }
    else
    {
        int bytes = 0;
        do
        {
            ret = fread(buffer, 1, BUFFER_SIZE, stdin);
            savedErrno = errno;
            if (ret > 0)
            {
                long written = smbc_write(fd, buffer, ret);
                if (written < 0)
                {
                    printError(savedErrno, path, "Error writing file.");
                    break;
                }
                else
                {
                    bytes += written;
                }
            }
        } while (ret > 0);

        smbc_close(fd);

        if (ret < 0)
        {
            printErrorAndExit(savedErrno, path, "Error reading from stdin.", ctx);
        }
        else
        {
            cout << "size: " << bytes << endl;
        }
    }
}

void mkdir(string path)
{
    int ret = smbc_mkdir(path.c_str(), 0777);
    if (ret < 0)
    {
        printError(errno, path, "Could not create directory.");
    }
}

void rmdir(string path)
{
    int ret = smbc_rmdir(path.c_str());
    if (ret < 0)
    {
        printError(errno, path, "Could not remove directory.");
    }
}

void rm(string path)
{
    int ret = smbc_unlink(path.c_str());
    if (ret < 0)
    {
        printError(errno, path, "Could not remove file.");
    }
}

void info(string path)
{
    struct stat st;
    if (smbc_stat(path.c_str(), &st) < 0)
    {
        printError(errno, path, "Could not get attributes of path.");
    }
    else
    {
        cout << "size: " << st.st_size << endl;
        cout << "lastmod: " << st.st_mtime << endl;
        cout << "mode: " << st.st_mode << endl;
    }
}

void create(string path)
{
    int fd = smbc_creat(path.c_str(), 0644);
    if (fd < 0)
    {
        printError(errno, path, "Could not create file.");
    }
    else
    {
        smbc_close(fd);
        cout << "File created successfully." << endl;
    }
}

void rename(string oldPath, string newPath)
{
    int ret = smbc_rename(oldPath.c_str(), newPath.c_str());
    if (ret < 0)
    {
        printError(errno, oldPath, "Could not rename file or directory.");
    }
}

int main(int argc, char *argv[])
{
    SMBCCTX *ctx = create_smbctx();
    if (ctx == NULL)
    {
        return -1;
    }

    bool recursive = false;
    bool children = false;
    bool readFlag = false;
    bool writeFlag = false;
    bool mkdirFlag = false;
    bool rmdirFlag = false;
    bool rmFlag = false;
    bool infoFlag = false;
    bool renameFlag = false;  // Добавлен новый флаг для переименования
    bool createFlag = false;  // Добавлен новый флаг для создания файлов
    bool enumerateFlag = false;

    // Проверяем переданные аргументы и устанавливаем флаги соответственно
    for (int i = 1; i < argc; i++)
    {
        string arg = argv[i];
        if (arg == "--recursive")
        {
            recursive = true;
        }
        else if (arg == "--children")
        {
            children = true;
        }
        else if (arg == "--read")
        {
            readFlag = true;
        }
        else if (arg == "--write")
        {
            writeFlag = true;
        }
        else if (arg == "--mkdir")
        {
            mkdirFlag = true;
        }
        else if (arg == "--rmdir")
        {
            rmdirFlag = true;
        }
        else if (arg == "--rm")
        {
            rmFlag = true;
        }
        else if (arg == "--info")
        {
            infoFlag = true;
        }
        else if (arg == "--rename")  // Добавлен новый флаг --rename
        {
            renameFlag = true;
        }
        else if (arg == "--create")  // Добавлен новый флаг --create
        {
            createFlag = true;
        }
        else if (arg == "--enumerate") // Добавляем обработку флага --enumerate
        {
            enumerateFlag = true;
        }
    }

    // Вызываем соответствующие функции в зависимости от флагов
    if (enumerateFlag && argc > 2)
    {
        enumerate(cout, ctx, recursive, children, argv[2]); // argv[2] содержит путь к директории
    }
    else if (readFlag && argc > 2)
    {
        read(argv[2], ctx);
    }
    else if (writeFlag && argc > 2)
    {
        write(argv[2], ctx);
    }
    else if (mkdirFlag && argc > 2)
    {
        mkdir(argv[2]);
    }
    else if (rmdirFlag && argc > 2)
    {
        rmdir(argv[2]);
    }
    else if (rmFlag && argc > 2)
    {
        rm(argv[2]);
    }
    else if (infoFlag && argc > 2)
    {
        info(argv[2]);
    }
    else if (renameFlag && argc > 3)  // Добавлено условие для переименования
    {
        rename(argv[2], argv[3]);
    }
    else if (createFlag && argc > 2)  // Добавлено условие для создания файла
    {
        create(argv[2]);
    }
    else
    {
        cout << "Invalid or missing arguments." << endl;
    }

    delete_smbctx(ctx);
    return 0;
}
