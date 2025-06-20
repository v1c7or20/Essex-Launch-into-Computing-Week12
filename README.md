# Essex-Launch-into-Computing
## End of Module Assignment - Part A

Languages choosen: Go and Python

Utility: Simple encryption tool

Utility usage:


### Python

python .\encypter.py  --mode encrypt --url  [url] --file_path [file|folder]

python .\encypter.py  --mode decrypt --private_key  [path_private_key] --file_path [file|folder]

To get the results of the profiler:

- Python: python -m snakeviz [file]

### Go

.\encrypter.exe -mode encrypt -url [url] -path [file|folder]

.\encrypter.exe -mode decrypt -private_key [path_private_key] -path [file|folder]


To get the results of the profiler:

- Go: go tool pprof [file]