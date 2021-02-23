# WindowsPostgresBackup
Performs backup and restores of postgres databases running on Windows

## Command line

**winPgBack** {params} [options]

### Params
**Use de form: --{param name}={param value}**

 param    | description       
----------|-------------------
 mode     | backup, restore 
 host     | localhost, IP address

#### Params in **backup** mode
 Param    | Description       
----------|-------------------
 port     | port number, i.e 5432
 user     | User with privileges to run pg_switch_wal()
 pwd      | Ciphered password. Use --makepwd *help function* to cipher a password
 path     | Backups directory
 bin      | Postgres binaries where pg_basebackup is

#### Params in **restore** mode
 Param    | Description       
----------|-------------------
 service  | Postgres service name, i.e. postgresql-x64-10
 path     | Backups directory
 wal      | WAL recovery path (WAL backup in postgres.conf::archive_command
 data     | Data directory, where base, .conf, pg_wal, log, etc. are
 rttime   | Recovery Target Time. (*default*: last moment before backup)

### Options
 Option       | Description       
--------------|-------------------
 sufix        | Backup files sufix. ("TS" = yyyyMMddHHmm time stamp only in backup mode)
 console      | Shows log in console, confirm restore, pause before close.
 logWithDebug | Log level = Debug, otherwise: Information
 logFormat    | Serilog log format, default: {Timestamp:HH:mm:ss.fff}\t[{Level:u3}]\t{Message:lj}\t{Exception}

### help functions
 Option       | Description       
--------------|-------------------
 makepwd      | Generates a ciphered password for a typed password in screen
 help         | Shows help in screen
 
## Examples

### Backup

> winPgBack --console --logWithDebug --mode=**backup** --host=localhost --port=5432 --user=postgres --pwd=**57A23B8A94DC578F34B6287A34FF58AC23D9** --path="C:\Backup\postgres\BAK" --bin="C:\Program files\PostgreSQL_v10\bin" --sufix=TS

### Restore

> winPgBack --console --logWithDebug --mode=**restore** --host=localhost --path="C:\Backup\postgres\BAK" --service="postgresql-x64-10" --wal="C:\Backup\postgres\WAL" --data="C:\Program files\PostgreSQL_v10\data" --sufix=202102152200

## Project
- Microsoft Visual Studio Community 2019
- .Net Core 5.0
- C#
- Console app

### Dependencies
- Npgsql
- Serilog
- SharpZipLib
