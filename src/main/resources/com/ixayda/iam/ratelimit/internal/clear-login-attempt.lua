if redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end

if redis.call('EXISTS', KEYS[2]) == 0 then
    redis.call('DEL', KEYS[1])
    return 0
end

redis.call('DEL', KEYS[1], KEYS[2])
return 1
