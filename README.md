# Essex-Launch-into-Computing
## End of Module Assignment - Part A

Languages choosen: Go and Python

Utility: Simple encryption tool

Utility usage:


### Python

python .\encypter.py  --mode encrypt --url  [url] --file_path [file|folder]

python .\encypter.py  --mode decrypt --private_key  [path_private_key] --file_path [file|folder]


https://github.com/user-attachments/assets/566ca49b-0f61-4c8e-a865-2a43a4b9d9de



To get the results of the profiler:

- Python: python -m snakeviz [file]

### Go

.\encrypter.exe -mode encrypt -url [url] -path [file|folder]

.\encrypter.exe -mode decrypt -private_key [path_private_key] -path [file|folder]


https://github.com/user-attachments/assets/13a49cf8-5c02-48c8-a95c-ef532af9aa24


To get the results of the profiler:

- Go: go tool pprof [file]
