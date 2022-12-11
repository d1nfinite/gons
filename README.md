# gons
go netstat library

## Install
```bash
go get github.com/d1nfinite/gons@latest
```

## Usage
```go
sockets, err := Sockets()
if err != nil {
    t.Fatal(err)
}

for _, s := range sockets {
    fmt.Printf("%+v\n", s)
}
```