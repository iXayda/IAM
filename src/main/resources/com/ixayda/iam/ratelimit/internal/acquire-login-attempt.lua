local principal_limit = tonumber(ARGV[1])
local principal_window = tonumber(ARGV[2])
local source_limit = tonumber(ARGV[3])
local source_window = tonumber(ARGV[4])

if not principal_limit or principal_limit <= 0 or not principal_window or principal_window <= 0
        or not source_limit or source_limit <= 0 or not source_window or source_window <= 0
        or not ARGV[5] or ARGV[5] == '' then
    return redis.error_reply('invalid login rate-limit arguments')
end

local function increment(key, window)
    local count = redis.call('INCR', key)
    local ttl = redis.call('PTTL', key)
    if count == 1 or ttl < 0 then
        redis.call('PEXPIRE', key, window)
        ttl = window
    end
    return count, ttl
end

local principal_count, principal_ttl = increment(KEYS[1], principal_window)
local source_count, source_ttl = increment(KEYS[2], source_window)
redis.call('SET', KEYS[3], ARGV[5], 'PX', math.max(principal_ttl, 1))
local retry_after = 0

if principal_count > principal_limit then
    retry_after = math.max(retry_after, principal_ttl, 1)
end
if source_count > source_limit then
    retry_after = math.max(retry_after, source_ttl, 1)
end

return retry_after
