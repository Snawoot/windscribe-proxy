FROM golang AS build

ARG GIT_DESC=undefined

WORKDIR /go/src/github.com/Snawoot/windscribe-proxy
COPY . .
RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-s -w -extldflags "-static" -X main.version='"$GIT_DESC"
ADD https://curl.haxx.se/ca/cacert.pem /certs.crt
RUN chmod 0644 /certs.crt
RUN mkdir /state

FROM scratch AS arrange
COPY --from=build /go/src/github.com/Snawoot/windscribe-proxy/windscribe-proxy /
COPY --from=build /certs.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=9999:9999 /state /state

FROM scratch
COPY --from=arrange / /
USER 9999:9999
EXPOSE 18080/tcp
ENTRYPOINT ["/windscribe-proxy", "-state-file", "/state/wndstate.json", "-bind-address", "0.0.0.0:28080"]
