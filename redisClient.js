const redis = require("redis");

const redisClient = redis.createClient({
    socket: {
        host: "127.0.0.1",
        port: 6379
    }
});

redisClient.on("error", (err) => {
    console.log("Redis Client Error", err);
});

(async () => {
    try {
        await redisClient.connect();
        console.log("Connected to Redis");
    } catch (err) {
        console.error("Redis Connection Error", err);
    }
})();

module.exports = redisClient;