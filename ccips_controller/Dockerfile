FROM golang

ADD . /ccips_controller



WORKDIR /ccips_controller/cmd/server
RUN go mod download
CMD ["go","run","main.go"]