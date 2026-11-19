# Scripted legitimate traffic for the lab. Runs on the internal lab network
# only (no internet), so everything it needs is installed at build time.
FROM mcr.microsoft.com/playwright:v1.65.1-noble
WORKDIR /suite
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY playwright.config.ts ./
COPY tests ./tests
ENV RESULTS_DIR=/results CI=1
ENTRYPOINT ["npx", "--no-install", "playwright", "test"]
