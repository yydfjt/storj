find . -name '*.go' -type f -print0 |
xargs -0 sed -i~ \
    -e 's,"net/http\([^a-zA-Z0-9_]\),"storj.io/storj/fork/net/http\1,g' \
    -e 's,"internal/,"storj.io/storj/internal/fork/,g' \
    -e 's,"golang_org/,"golang.org/,g'

find . -name '*.go~' -delete
