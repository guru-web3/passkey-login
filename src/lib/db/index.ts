import Redis from 'ioredis';

if (!process.env.REDIS_URL) {
  throw Error('REDIS_URL env not set');
}
export const redisClient = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,
});

export default redisClient;
