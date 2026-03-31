FROM node:20-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy all source files
COPY . .

EXPOSE 5173

# Run the vite development server with host bindings
CMD ["npm", "run", "dev", "--", "--host"]
