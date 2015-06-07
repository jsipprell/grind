FROM golang:latest

# Notes:
# To run, do something like:
# docker run -d -p 61612:61612 --link=NSQD:nsqd --link=NSQLOOKUPD:nsqlookupd --name=STOMP stomp2nsq:latest
# (assuming you already have two other containers running for nsqd and nsqlooupd named NSQD/NSQLOOKUPD)

EXPOSE 53

ENV CGO_ENABLED 0
COPY scripts/gpm /usr/local/bin/gpm
ADD . $GOPATH/src/github.com/jsipprell/grind
RUN cd $GOPATH/src/github.com/jsipprell/grind && /usr/local/bin/gpm && go build -tags netgo && go install
CMD ["/gopath/bin/grind"]
