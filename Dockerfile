# 1. ベースとなるイメージ（Goが入っている軽量なDebian系）
FROM golang:1.24-bullseye

# 2. ネットワーク操作に必要なパッケージをインストール
# iproute2: ipコマンド用 / iptables: ルーティング用 / tcpdump: パケット確認用
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    tcpdump \
    iputils-ping \
    net-tools \
    curl \
    libpcap-dev \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

# 3. コンテナ内の作業ディレクトリを設定
WORKDIR /app

# 4. 依存関係のキャッシュ（go.modを先にコピーして、ライブラリだけ先にDLする）
COPY go.mod ./
# もし go.sum が既にあるなら、下の行のコメントアウトを外す
# COPY go.sum ./
RUN go mod download

# 5. ソースコードをコピー
COPY . .

# 6. コンテナ起動時に実行されるデフォルトコマンド
# ここでは「bash」にしておき、中に入ってから go run できるようにします
CMD ["/bin/bash"]