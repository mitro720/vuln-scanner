FROM node:20-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy application source code
COPY . .

EXPOSE 5000

# Start backend server
CMD ["node", "src/server.js"]
