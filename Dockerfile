FROM rustlang/rust:nightly

WORKDIR /vault

COPY . .

CMD ["cargo", "test"]
