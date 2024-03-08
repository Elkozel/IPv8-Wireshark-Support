superapp_proto = Proto("superapp", "Tribler Trustchain Superapp")

-- General Parsing logic
local Utils = {}

function Utils:parseIPv4(buffer, pinfo, tree, gloablOffset)
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

function Utils:parseULong(buffer, pingo, tree, globalOffset)
    local offset = globalOffset

    local long = buffer(offset, 8)
    offset = offset + 8

    return offset, long
end

function Utils:parseUInt(buffer, pingo, tree, globalOffset)
    local offset = globalOffset

    local long = buffer(offset, 4)
    offset = offset + 4

    return offset, long
end

function Utils:parseString(buffer, pinfo, tree, globalOffset)
    local offset = globalOffset

    local size = buffer(offset, 1):uint()
    offset = offset + 1

    local string = buffer(offset, size)
    offset = offset + size

    return offset, string
end


-- IPv8 Protocol
local IPv8 = {
    Protocols = { [0] = "IPv8" },
    Messages = {}
}

function IPv8:parsePrefix(buffer, pinfo, tree)
    local offset = 0

    -- Parse protocol
    local protocol = buffer(offset, 1)
    local protocolName = self.Protocols[protocol:uint()] or "Unidentified"
    offset = offset + 1

    -- Parse version
    local version = buffer(offset, 1)
    offset = offset + 1

    -- Parse service ID
    local serviceID = buffer(offset, 20)
    offset = offset + 20
    
    -- Add prefix to the tree
    local subtree = tree:add(buffer(0, offset), "Prefix: [" .. protocolName .. " v" .. version:uint() .. "]")
    subtree:add(protocol, "Protocol: " .. protocolName .. " (" .. protocol:uint() .. ")")
    subtree:add(version, "Version: " .. version:uint())
    subtree:add(serviceID, "Service ID: " .. serviceID:string())

    -- Return the offset and tree
    local remainder = buffer(offset)
    return remainder, subtree
end


function IPv8:parseGlobalTime(buffer, pinfo, tree)
    local offset = 0

    local clock = buffer(offset, 8)
    tree:add(clock, "Clock: " .. clock:uint64())
    offset = offset + 8

    local remainder = buffer(offset)
    return remainder, tree
end

function IPv8:parseSignature(buffer, pinfo, tree)
    if buffer:len() < 64 then
        return buffer, nil
    end

    local signature = buffer(buffer:len() - 64, 64)
    local remainder = buffer(0, buffer:len() - 64)

    return remainder, signature
end

function IPv8:parseAuthenticationPayload(buffer, pinfo, tree)
    local offset = 0

    -- See the length of the payload
    local len = buffer(offset, 2)
    offset = offset + 2

    -- If it is zero, the payload is not authenticated
    if len:uint() == 0 then
        local subtree = tree:add(buffer(0, offset), "Authentication payload: " .. "(Unsigned)")
        subtree:add(len, "Length: " .. len:uint())

        return buffer(offset), subtree
    end

    local public_key = buffer(offset, len:uint())
    local offset = offset + len:uint()

    local remainder, signature = IPv8:parseSignature(buffer, pinfo, tree)

    local subtree = tree:add(buffer(0, offset),
        "Authentication payload: " .. "(Signed " .. len:uint() .. " bytes)")
    subtree:add(len, "Length: " .. len:uint())
    subtree:add(public_key, "Public Key: " .. public_key:string())
    subtree:add(signature, "Signature: " .. signature:string())

    return remainder(offset), subtree
end

function IPv8:parseIPv8(buffer, pinfo, tree)

    -- Parse the prefix
    local buffer, prefix = IPv8:parsePrefix(buffer, pinfo, tree)
    
    local msgID = buffer(0, 1)
    buffer = buffer(1)

    -- Parse signnature if authenticated
    if IPv8.Messages[msgID:uint()] ~= nil and IPv8.Messages[msgID:uint()].auth == true then
        buffer, signature = IPv8:parseAuthenticationPayload(buffer, pinfo, tree)
    end

    -- Parse clock
    local buffer, clock = IPv8:parseGlobalTime(buffer, pinfo, tree)

    return buffer, msgID
end

local function parseEVAWriteRequest(buffer, pinfo, tree)
    local offset = 0
    
    local offset, Info = Utils:parseString(buffer, pinfo, tree, offset)
    tree:add(Info, "Info: " .. Info:string())
    
    local offset, ID = Utils:parseString(buffer, pinfo, tree, offset)
    tree:add(ID, "ID: " .. ID:string())
    
    local offset, nonce = Utils:parseULong(buffer, pinfo, tree, offset)
    tree:add(nonce, "Nonce: " .. nonce:uint64())
    
    local offset, dataSize = Utils:parseULong(buffer, pinfo, tree, offset)
    tree:add(dataSize, "Data Size: " .. dataSize:uint64())

    local offset, blockCount = Utils:parseUInt(buffer, pinfo, tree, offset)
    tree:add(blockCount, "Block Count: " .. blockCount:uint64())

    local offset, blockSize = Utils:parseUInt(buffer, pinfo, tree, offset)
    tree:add(blockSize, "Block Size: " .. blockSize:uint64())
    
    local offset, windowSize = Utils:parseUInt(buffer, pinfo, tree, offset)
    tree:add(windowSize, "Window Size: " .. windowSize:uint64())

    return buffer(0, offset)
end

IPv8.Messages[130] = {
    id = 130,
    app = "",
    name = "EWA Write Request",
    parse = parseEVAWriteRequest,
    auth = true
}

local function parseEVAAcknowledgement(buffer, pinfo, tree)
    local offset = 0
    
    local offset, nonce = Utils:parseULong(buffer, pinfo, tree, offset)
    tree:add(nonce, "Nonce: " .. nonce:uint64())

    local offset, ackWindow = Utils:parseUInt(buffer, pinfo, tree, offset)
    tree:add(ackWindow, "ACK Window: " .. ackWindow:uint())

    local unAckedBlocks = buffer(offset)
    offset = offset + unAckedBlocks:len()
    tree:add(unAckedBlocks, "UnACKed Blocks: " .. unAckedBlocks:raw())

    return buffer(0, offset)
end

IPv8.Messages[131] = {
    id = 131,
    app = "",
    name = "EVA Acknowledgement",
    parse = parseEVAAcknowledgement,
    auth = true
}

local function parseEVADataPayload(buffer, pinfo, tree)
    local offset = 0

    local offset, blockNumber = Utils:parseUInt(buffer, pinfo, tree, offset)
    tree:add(blockNumber, "Block Number: " .. blockNumber:uint())
    
    local offset, nonce = Utils:parseULong(buffer, pinfo, tree, offset)
    tree:add(nonce, "Nonce: " .. nonce:uint64())

    local data = buffer(offset)
    offset = offset + data:len()
    tree:add(data, "Data: " .. data:raw())

    return buffer(0, offset)
end

IPv8.Messages[132] = {
    id = 132,
    app = "",
    name = "EVA Data",
    parse = parseEVADataPayload,
    auth = true
}

local function parseEVAError(buffer, pinfo, tree)
    local offset = 0

    local offset, info = Utils:parseString(buffer, pinfo, tree, offset)
    tree:add(info, "Block Number: " .. info:string())
    
    local offset, message = Utils:parseString(buffer, pinfo, tree, offset)
    tree:add(message, "Nonce: " .. message:string())

    return buffer(0, offset)
end

IPv8.Messages[133] = {
    id = 133,
    app = "",
    name = "EVA Error",
    parse = parseEVAError,
    auth = true
}


local function parseIntroductionResponse(buffer, pinfo, tree)
    local offset = 0

    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Destination Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source LAN Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source WAN Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "LAN Introduction Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "WAN Introduction Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    
    local connectionType = buffer(offset, 1)
    tree:add(connectionType, "Connection Type: " .. connectionType:uint())
    offset = offset + 1

    -- Identifier
    local identifier = buffer(offset, 2)
    tree:add(identifier, "Identifier: " .. identifier:uint())
    offset = offset + 2
    
    -- Extra Bytes?
    if buffer:len() > offset then
        local extraBytes = buffer(offset)
        tree:add(extraBytes, "Extra Bytes: " .. extraBytes:string())
        offset = offset + extraBytes:len()
    end
    
    return buffer(0, offset)
end

IPv8.Messages[245] = {
    id = 245,
    app = "",
    name = "Introduction Response",
    parse = parseIntroductionResponse,
    auth = true
}

local function parseIntroductionRequest(buffer, pinfo, tree)
    local offset = 0

    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Destination Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source LAN Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source WAN Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    local connectionType = buffer(offset, 1)
    tree:add(connectionType, "Connection Type: " .. connectionType:uint())
    offset = offset + 1

    -- Identifier
    local identifier = buffer(offset, 2)
    tree:add(identifier, "Identifier: " .. identifier:uint())
    offset = offset + 2
    
    -- Extra Bytes?
    if buffer:len() > offset then
        local extraBytes = buffer(offset)
        tree:add(extraBytes, "Extra Bytes: " .. extraBytes:string())
        offset = offset + extraBytes:len()
    end
    
    return buffer(0, offset)
end


IPv8.Messages[246] = {
    id = 246,
    app = "",
    name = "Introduction Request",
    parse = parseIntroductionRequest,
    auth = true
}

local function parsePuncturePacket(buffer, pinfo, tree)
    local offset = 0
    -- Destination IP
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Source Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- Source IP
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "Destination Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- Identifier
    local id = buffer(offset, 2)
    tree:add(id, "Identifier: " .. id:uint())
    offset = offset + 2

    return buffer(0, offset)
end

IPv8.Messages[249] = {
        id = 249,
        app = "",
        name = "Puncture Packet",
        parse = parsePuncturePacket,
        auth = true
}

local function parsePunctureRequestPayload(buffer, pinfo, tree)
    local offset = 0
    -- IP 1
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "LAN Walker Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- IP 2
    local offset, IP = Utils:parseIPv4(buffer, pinfo, tree, offset)
    tree:add(IP.buffer, "WAN Walker Address: " .. IP.p1 .. "." .. IP.p2 .. "." .. IP.p3 .. "." .. IP.p4 .. ":" .. IP.port)

    -- Identifier
    local id = buffer(offset, 2)
    tree:add(id, "Puncture Request Identifier: " .. id:uint())
    offset = offset + 2

    return buffer(0, offset)
end

IPv8.Messages[250] = {
    id = 250,
    app = "",
    name = "Puncture Request",
    parse = parsePunctureRequestPayload,
    auth = false
}

IPv8.Messages[251] = {
    id = 251,
    app = "",
    name = "Puncture Test",
    parse = parsePunctureRequestPayload,
    auth = false
}

local function parseOpenPortPayload(buffer, pinfo, tree)
    local offset = 0

    local portToOpen = buffer(0,2)
    offset = offset + 2
    tree:add(portToOpen, "Port to open: " .. portToOpen:uint())

    return buffer(0, offset)
end

IPv8.Messages[252] = {
    id = 251,
    app = "",
    name = "Port Open Request",
    parse = parseOpenPortPayload,
    auth = false
}
IPv8.Messages[253] = {
    id = 251,
    app = "",
    name = "Port Open Response",
    parse = parseOpenPortPayload,
    auth = false
}




-- create a function to dissect it
function superapp_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Tribler Trustchain Superapp"
    -- Parse IPv8
    local IPv8_Protocol = tree:add(superapp_proto, buffer(), "IPv8")
    local buffer, msgID = IPv8:parseIPv8(buffer, pinfo, IPv8_Protocol)

    -- Get the message parser or just show "Unknown"
    local msgParser = IPv8.Messages[msgID:uint()] or {id = msgID:uint(), name = "Unknown"}
    -- Add the msgID to the protocol header
    IPv8_Protocol:add(msgID, "Message ID: " .. msgParser.id .. " (".. msgParser.name ..")")

    if msgParser.parse ~= nil then
        local superapp = tree:add(superapp_proto, buffer(), "Trustchain Superapp (" .. msgParser.name .. ")")
        buffer = msgParser.parse(buffer, pinfo, superapp)
    end

end

-- register our protocol to handle udp port 8060
udp_table = DissectorTable.get("udp.port")
udp_table:add(8090, superapp_proto)
