-- declare our protocol
superapp_proto = Proto("superapp", "Tribler Trustchain Superapp")

local Protocols = { [0] = "IPv8" }

local function parsePrefix(buffer, pinfo, tree, globalOffset)
    local offset = globalOffset

    -- Parse protocol
    local protocol = buffer(offset, 1)
    local protocolName = Protocols[protocol:uint()]

    if protocolName == nil then
        protocolName = "Unidentified"
    end
    offset = offset + 1

    -- Parse version
    local version = buffer(offset, 1)
    offset = offset + 1

    -- Parse service ID
    local serviceID = buffer(offset, 20)
    offset = offset + 20

    -- Return the offset and tree
    local subtree = tree:add(buffer(globalOffset, offset - globalOffset), "Prefix: " .. "[v" .. version:uint() .. "]")
    subtree:add(protocol, "Protocol: " .. protocolName .. " (" .. protocol:uint() .. ")")
    subtree:add(version, "Version: " .. version:uint())
    subtree:add(serviceID, "Service ID: " .. serviceID:string())
    return offset, subtree
end


local function parseBinMemberAuthenticationPayload(buffer, pinfo, tree, globalOffset)
    local offset = globalOffset

    local len = buffer(offset, 2)
    offset = offset + 2

    if len:uint() == 0 then
        local subtree = tree:add(buffer(globalOffset, offset - globalOffset), "Authentication payload: " .. "(Unsigned)")
        subtree:add(len, "Length: " .. len:uint())

        return offset, subtree
    end

    local sign = buffer(offset, len:uint())
    local offset = offset + len:uint()

    local subtree = tree:add(buffer(globalOffset, offset - globalOffset),
        "Authentication payload: " .. "(Signed " .. len:uint() .. " bytes)")
    subtree:add(len, "Length: " .. len:uint())
    subtree:add(sign, "Signature: " .. sign:string())

    return offset, subtree
end


local function parseGlobalTimeDistributionPayload(buffer, pinfo, tree, offset)
    local clock = buffer(offset, 8)
    tree:add(clock, "Clock: " .. clock:uint64())
    offset = offset + 8

    return offset, tree
end

local function parseIPv4(buffer, pinfo, tree, gloablOffset)
    local offset = gloablOffset

    local p1 = buffer(offset, 1):uint()
    offset = offset + 1
    local p2 = buffer(offset, 1):uint()
    offset = offset + 1
    local p3 = buffer(offset, 1):uint()
    offset = offset + 1
    local p4 = buffer(offset, 1):uint()
    offset = offset + 1
    local port = buffer(offset, 2):uint()
    offset = offset + 2

    return offset, { p1 = p1, p2 = p2, p3 = p3, p4 = p4, port = port, buffer = buffer(gloablOffset, offset - gloablOffset) }
end

local function parsePuncturePacket(buffer, pinfo, tree, offset)
    -- Destination IP
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- Source IP
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Destination Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- Identifier
    local id = buffer(offset, 2)
    tree:add(id, "Identifier: " .. id:uint())
    offset = offset + 2

    return offset, tree
end

local function parsePunctureRequestPayload(buffer, pinfo, tree, offset)
    -- IP 1
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "LAN Walker Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- IP 2
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "WAN Walker Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- Identifier
    local id = buffer(offset, 2)
    tree:add(id, "Puncture Request Identifier: " .. id:uint())
    offset = offset + 2

    return offset, tree
end


local function parseIntroductionRequest(buffer, pinfo, tree, offset)
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Destination Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source LAN Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source WAN Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    local connectionType = buffer(offset, 1)
    tree:add(connectionType, "Connection Type: " .. connectionType:uint())
    offset = offset + 1

    -- Identifier
    local identifier = buffer(offset, 2)
    tree:add(identifier, "Identifier: " .. identifier:uint())
    offset = offset + 2
    
    local extraBytes = buffer(offset)
    offset = offset + extraBytes:len()
    
    return offset, tree
end

local Messages = {
    [250] = {
        id = 250,
        name = "Puncture Request",
        parse = parsePunctureRequestPayload,
        auth = false
    },
    [249] = {
        id = 249,
        name = "Puncture Packet",
        parse = parsePuncturePacket,
        auth = true
    },
    [246] = {
        id = 246,
        name = "Introduction Request",
        parse = parseIntroductionRequest,
        auth = true
    },
    [245] = {
        id = 245,
        name = "Introduction Response",
        parse = nil,
        auth = true
    }
}

local function parseIPv8(buffer, pinfo, tree, offset, msgID)

    -- Parse signnature if authenticated
    if Messages[msgID] ~= nil and Messages[msgID].auth == true then
        offset, signature = parseBinMemberAuthenticationPayload(buffer, pinfo, tree, offset)
    end

    -- Parse clock
    local offset, clock = parseGlobalTimeDistributionPayload(buffer, pinfo, tree, offset)

    return offset, tree
end

local function parseSignature(buffer, pinfo, tree, offset)
    local signature = buffer(offset, 64)
    local offset = offset + 64

    return offset, signature
end

local function parseMessage(buffer, pinfo, tree, offset)
    local msgID = buffer(offset, 1)
    offset = offset + 1

    offset, tree = parseIPv8(buffer, pinfo, tree, offset, msgID:uint())

    local msgParser = Messages[msgID:uint()]

    if msgParser ~= nil then
        tree:add(msgID, "Message ID: " .. msgParser.id .. " (".. msgParser.name ..")")
        offset, tree = msgParser.parse(buffer, pinfo, tree, offset)
    else
        tree:add(msgID, "Message ID: " .. msgID:uint() .. " (Unknown)")
    end

    -- Parse signnature if authenticated
    if Messages[msgID:uint()] ~= nil and Messages[msgID:uint()].auth == true then
        local offset, signature = parseSignature(buffer, pinfo, tree, offset)
        tree:add(signature, "Signature: " .. signature:string())
    end

    return offset
end



-- create a function to dissect it
function superapp_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Tribler Trustchain Superapp"
    local subtree = tree:add(superapp_proto, buffer(), "Trustchain Superapp Data")
    local offset = 0

    -- Parse the prefix
    offset, prefix = parsePrefix(buffer, pinfo, subtree, offset)

    -- Parse the actual message
    offset = parseMessage(buffer, pinfo, subtree, offset)
end

-- register our protocol to handle udp port 8060
udp_table = DissectorTable.get("udp.port")
udp_table:add(8090, superapp_proto)
