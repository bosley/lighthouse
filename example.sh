make clean && make
# Define the testing directory as a variable
TESTING_DIR="/tmp/testing"

rm -rf "$TESTING_DIR"
mkdir -p "$TESTING_DIR"
./lighthouse --new --ssl "$TESTING_DIR"
./lighthouse --new --db "$TESTING_DIR/test.db"

export LIGHTHOUSE_SECRET_KEY=$(openssl rand -base64 32) && \
    ./lighthouse --cert "$TESTING_DIR/server.crt" --key "$TESTING_DIR/server.key" --db "$TESTING_DIR/test.db"

