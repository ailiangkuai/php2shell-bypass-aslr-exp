# 1. 刷新系统软件源缓存
yum clean all
yum makecache --refresh

# 2. 安装基础工具
yum install -y dnf-plugins-core git curl wget vim unzip tar

# 3. 添加 Docker 官方仓库
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 4. 安装 Docker、Docker Compose
yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 5. 启动 Docker 并设置开机自启
systemctl enable --now docker

# 6. 验证安装
docker --version
docker compose version
git --version
docker ps