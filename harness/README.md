# Harness

This is a test harness one can use to benchmark the library

## How to use

Run following command in Linux to test throughput of 1 000 000 000 bytes

```bash
dotnet run -c release 1000000000 < /dev/zero > /dev/null
```

or if you do not want any limit

```bash
dotnet run -c release < /dev/zero > /dev/null
```
