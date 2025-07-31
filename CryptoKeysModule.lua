local CryptoKeysModule = {}

-- Informações do módulo
CryptoKeysModule.Info = {
    Name = "CryptoKeysModule",
    Version = "1.1.0",
    Author = "DragonMODS",
    Description = "Banco de chaves expandido para quebra de criptografia",
    LastUpdate = os.time()
}

-- Chaves numéricas mais usadas em obfuscadores
CryptoKeysModule.NumericKeys = {
    -- Chaves básicas
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    
    -- Chaves de bytes
    16, 32, 64, 128, 255, 256, 512, 1024, 2048, 4096, 8192,
    
    -- Chaves hexadecimais comuns
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF, 0x100,
    0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0x1337, 0xABCD, 0xFFFF, 0x7FFF,
    
    -- Chaves específicas de obfuscadores
    13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, -- Números primos
    69, 420, 666, 777, 888, 999, 1337, 1234, 5678, 9999, 10000,
    
    -- Chaves de ano/data
    2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028,
    
    -- Chaves matemáticas especiais
    314159, 271828, 161803, 141421, 2.71828, 3.14159, -- Pi, e, phi, sqrt(2), e, pi
    123456, 654321, 111111, 222222, 333333, 444444, 555555, 666666,
    
    -- Chaves de sequência
    112233, 445566, 778899, 123321, 456654, 789987
}

-- Chaves de string/texto comuns
CryptoKeysModule.StringKeys = {
    -- Chaves simples
    "a", "b", "c", "x", "y", "z", "k", "s", "q", "w", "e", "r", "t",
    
    -- Palavras comuns em obfuscação
    "key", "code", "data", "text", "info", "value", "item", "secret", "token",
    "hack", "cheat", "script", "game", "player", "user", "password", "auth",
    
    -- Nomes de obfuscadores/exploits
    "luraph", "psu", "ironbrew", "synapse", "krnl", "oxygen",
    "jjsploit", "delta", "sentinel", "protosmasher", "fluxus", "comet",
    
    -- Termos técnicos
    "encrypt", "decrypt", "encode", "decode", "obfuscate", "deobfuscate",
    "compile", "bytecode", "source", "binary", "ascii", "utf8", "unicode", "hash",
    
    -- Roblox específico
    "roblox", "rbx", "studio", "exploit", "admin", "owner", "dev",
    "localplayer", "workspace", "game", "players", "services", "replicatedstorage",
    "serverscriptservice", "startergui", "starterplayer",
    
    -- Combinações alfanuméricas
    "abc", "xyz", "123", "abc123", "123abc", "test123", "key123",
    "admin123", "pass123", "code123", "data123", "user123", "game123",
    
    -- Palavras relacionadas a segurança
    "secure", "crypto", "cipher", "algorithm", "protection", "lock", "unlock"
}

-- Chaves de caracteres especiais e símbolos
CryptoKeysModule.SymbolKeys = {
    -- Símbolos básicos
    "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=",
    "[", "]", "{", "}", "|", "\\", ":", ";", "'", "\"", "<", ">", ",", ".", "?", "/",
    
    -- Combinações de símbolos
    "!@#", "$%^", "&*(", ")_+", "=-[]", "{}|\\", ":;'\"", "<>,.?/",
    "!@#$%", "^&*()", "-_=+", "[{}]", "|\\:;",
    
    -- Espaços e caracteres de controle
    " ", "\t", "\n", "\r", "\0",
    
    -- ASCII especiais (códigos de caracteres)
    string.char(0), string.char(1), string.char(2), string.char(3), string.char(4),
    string.char(127), string.char(255), string.char(128), string.char(64), string.char(32),
    string.char(10), string.char(13)
}

-- Chaves Base64 comuns (decodificadas)
CryptoKeysModule.Base64Keys = {
    "YWRtaW4=",     -- admin
    "cGFzcw==",     -- pass
    "a2V5",         -- key
    "Y29kZQ==",     -- code
    "ZGF0YQ==",     -- data
    "dGV4dA==",     -- text
    "cm9ibG94",     -- roblox
    "c2NyaXB0",     -- script
    "aGFjaw==",     -- hack
    "ZXhwbG9pdA==", -- exploit
    "ZW5jcnlwdA==", -- encrypt
    "ZGVjcnlwdA==", -- decrypt
    "b2JmdXNjYXRl", -- obfuscate
    "bHVyYXBo",     -- luraph
    "cHN1",         -- psu
    "aXJvbmJyZXc=", -- ironbrew
    "c3luYXBzZQ==", -- synapse
    "a3JubA==",     -- krnl
    "ZGVsdGE=",     -- delta
    "Zmx1eHVz",     -- fluxus
    "Y29tZXQ=",     -- comet
    "c2VjdXJl",     -- secure
    "Y3J5cHRv"      -- crypto
}

-- Chaves de deslocamento (shift) para Caesar cipher
CryptoKeysModule.ShiftKeys = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17, -18, -19, -20, -21, -22, -23, -24, -25,
    26, 27, 28, 29, 30, -- Extended shifts
    -26, -27, -28, -29, -30
}

-- Chaves XOR específicas (mais usadas)
CryptoKeysModule.XorKeys = {
    -- Chaves single-byte
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    
    -- Chaves específicas comuns
    42, 69, 123, 255, 127, 63, 31, 15, 7, 3, 1, 2, 4, 8, 16,
    
    -- Chaves multi-byte (como arrays)
    {0x12, 0x34}, {0xAB, 0xCD}, {0xFF, 0x00}, {0x00, 0xFF},
    {0x12, 0x34, 0x56}, {0xAB, 0xCD, 0xEF}, {0x11, 0x22, 0x33},
    {0x01, 0x02, 0x03, 0x04}, {0xFF, 0xFE, 0xFD, 0xFC},
    {0xAA, 0xBB, 0xCC}, {0x12, 0x34, 0x56, 0x78}
}

-- Padrões de chaves usados em diferentes obfuscadores
CryptoKeysModule.ObfuscatorKeys = {
    -- Luraph
    luraph = {
        numeric = {1337, 2021, 123456, 0xDEADBEEF, 0xBADF00D},
        strings = {"luraph", "obf", "protected", "anti", "secure_luraph"},
        patterns = {"^luraph_", "_obf$", "protected_", "luraph_key_"}
    },
    
    -- PSU
    psu = {
        numeric = {69, 420, 1234, 5678, 9999},
        strings = {"psu", "getfenv", "setfenv", "env", "psu_secure"},
        patterns = {"psu_", "_env", "getfenv_", "psu_key_"}
    },
    
    -- IronBrew
    ironbrew = {
        numeric = {32, 64, 128, 256, 512},
        strings = {"ironbrew", "bit32", "bxor", "rshift", "lshift"},
        patterns = {"ib_", "_bit", "brew_", "iron_key_"}
    },
    
    -- Synapse
    synapse = {
        numeric = {777, 1337, 9999, 1111},
        strings = {"syn", "synapse", "crypt", "secure", "syn_x"},
        patterns = {"syn_", "_crypt", "secure_", "syn_key_"}
    },
    
    -- Fluxus
    fluxus = {
        numeric = {123, 456, 789, 1010},
        strings = {"fluxus", "exploit", "secure", "flux"},
        patterns = {"flux_", "_exp", "secure_flux_"}
    }
}

-- Função para obter todas as chaves numéricas
function CryptoKeysModule:GetNumericKeys()
    return self.NumericKeys
end

-- Função para obter todas as chaves de string
function CryptoKeysModule:GetStringKeys()
    return self.StringKeys
end

-- Função para obter chaves XOR
function CryptoKeysModule:GetXorKeys()
    return self.XorKeys
end

-- Função para obter chaves de deslocamento
function CryptoKeysModule:GetShiftKeys()
    return self.ShiftKeys
end

-- Função para obter chaves Base64
function CryptoKeysModule:GetBase64Keys()
    return self.Base64Keys
end

-- Função para obter chaves de símbolos
function CryptoKeysModule:GetSymbolKeys()
    return self.SymbolKeys
end

-- Função para obter chaves de obfuscador específico
function CryptoKeysModule:GetObfuscatorKeys(obfuscatorName)
    if self.ObfuscatorKeys[obfuscatorName] then
        return self.ObfuscatorKeys[obfuscatorName]
    end
    return nil
end

-- Função para obter TODAS as chaves
function CryptoKeysModule:GetAllKeys()
    local allKeys = {
        numeric = self.NumericKeys,
        strings = self.StringKeys,
        symbols = self.SymbolKeys,
        base64 = self.Base64Keys,
        shifts = self.ShiftKeys,
        xor = self.XorKeys,
        obfuscators = self.ObfuscatorKeys
    }
    return allKeys
end

-- Função para contar total de chaves
function CryptoKeysModule:CountKeys()
    local total = 0
    total = total + #self.NumericKeys
    total = total + #self.StringKeys
    total = total + #self.SymbolKeys
    total = total + #self.Base64Keys
    total = total + #self.ShiftKeys
    total = total + #self.XorKeys
    
    -- Conta chaves de obfuscadores
    for _, obf in pairs(self.ObfuscatorKeys) do
        total = total + #obf.numeric + #obf.strings + #obf.patterns
    end
    
    return total
end

-- Função para gerar chaves customizadas baseadas em padrão
function CryptoKeysModule:GenerateCustomKeys(pattern, count)
    local keys = {}
    count = count or 10
    
    if pattern == "incremental" then
        for i = 1, count do
            table.insert(keys, i)
        end
    elseif pattern == "powers_of_2" then
        for i = 0, count - 1 do
            table.insert(keys, 2^i)
        end
    elseif pattern == "fibonacci" then
        local a, b = 1, 1
        for i = 1, count do
            table.insert(keys, a)
            a, b = b, a + b
        end
    elseif pattern == "primes" then
        local function isPrime(n)
            if n < 2 then return false end
            for i = 2, math.sqrt(n) do
                if n % i == 0 then return false end
            end
            return true
        end
        
        local num = 2
        while #keys < count do
            if isPrime(num) then
                table.insert(keys, num)
            end
            num = num + 1
        end
    elseif pattern == "random_hex" then
        for i = 1, count do
            table.insert(keys, string.format("0x%X", math.random(0, 0xFFFF)))
        end
    elseif pattern == "alphanumeric" then
        local chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        for i = 1, count do
            local key = ""
            for j = 1, 6 do
                key = key .. chars:sub(math.random(1, #chars), math.random(1, #chars))
            end
            table.insert(keys, key)
        end
    end
    
    return keys
end

-- Função para obter informações do módulo
function CryptoKeysModule:GetInfo()
    local info = {}
    for k, v in pairs(self.Info) do
        info[k] = v
    end
    info.TotalKeys = self:CountKeys()
    return info
end

-- Função para verificar se uma chave existe
function CryptoKeysModule:KeyExists(key, keyType)
    if keyType == "numeric" then
        for _, v in ipairs(self.NumericKeys) do
            if v == key then return true end
        end
    elseif keyType == "string" then
        for _, v in ipairs(self.StringKeys) do
            if v == key then return true end
        end
    elseif keyType == "symbol" then
        for _, v in ipairs(self.SymbolKeys) do
            if v == key then return true end
        end
    elseif keyType == "base64" then
        for _, v in ipairs(self.Base64Keys) do
            if v == key then return true end
        end
    elseif keyType == "shift" then
        for _, v in ipairs(self.ShiftKeys) do
            if v == key then return true end
        end
    elseif keyType == "xor" then
        for _, v in ipairs(self.XorKeys) do
            if type(v) == "table" then
                if table.concat(v) == table.concat(key) then return true end
            elseif v == key then
                return true
            end
        end
    end
    return false
end

-- Função para adicionar nova chave
function CryptoKeysModule:AddKey(key, keyType)
    if not self:KeyExists(key, keyType) then
        if keyType == "numeric" then
            table.insert(self.NumericKeys, key)
        elseif keyType == "string" then
            table.insert(self.StringKeys, key)
        elseif keyType == "symbol" then
            table.insert(self.SymbolKeys, key)
        elseif keyType == "base64" then
            table.insert(self.Base64Keys, key)
        elseif keyType == "shift" then
            table.insert(self.ShiftKeys, key)
        elseif keyType == "xor" then
            table.insert(self.XorKeys, key)
        end
        return true
    end
    return false
end

-- Log de carregamento
print("🔑 CryptoKeysModule v" .. CryptoKeysModule.Info.Version .. " carregado!")
print("📊 Total de chaves disponíveis: " .. CryptoKeysModule:CountKeys())
print("🎯 Pronto para quebra de criptografia!")

return CryptoKeysModule
