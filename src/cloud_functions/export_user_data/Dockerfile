FROM golang:1.20

# Copy local code to the container image
ENV APP_HOME /mirai
COPY / $APP_HOME
WORKDIR $APP_HOME

# Install dependencies
RUN go mod download

# Build the binary
RUN go build -o mirai_service

# Run the web service on container startup
ENV PORT 8080
CMD ["./mirai_service"]