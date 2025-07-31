local CryptoKeysModule = {}

-- Informações do módulo
CryptoKeysModule.Info = {
    Name = "CryptoKeysModule", 
    Version = "1.0.0",
    Author = "Delta Team",
    Description = "Banco de chaves para quebra de criptografia",
    LastUpdate = os.time()
}

-- Chaves numéricas mais usadas em obfuscadores
CryptoKeysModule.NumericKeys = {
    -- Chaves básicas
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    
    -- Chaves de bytes
    16, 32, 64, 128, 255, 256, 512, 1024, 2048,
    
    -- Chaves hexadecimais comuns
    0x01, 0x02, 0x10, 0x20, 0x40, 0x80, 0xFF, 0x100,
    0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0x1337, 0xABCD,
    
    -- Chaves específicas de obfuscadores
    13, 17, 19, 23, 29, 31, 37, 41, 43, 47, -- Números primos
    69, 420, 666, 777, 888, 999, 1337, 1234, 5678, 9999,
    
    -- Chaves de ano/data
    2020, 2021, 2022, 2023, 2024, 2025,
    
    -- Chaves matemáticas especiais  
    314159, 271828, 161803, 141421, -- Pi, e, phi, sqrt(2)
    123456, 654321, 111111, 222222, 333333
}

-- Chaves de string/texto comuns
CryptoKeysModule.StringKeys = {
    -- Chaves simples
    "a", "b", "c", "x", "y", "z", "k", "s",
    
    -- Palavras comuns em obfuscação
    "key", "code", "data", "text", "info", "value", "item",
    "hack", "cheat", "script", "game", "player", "user",
    
    -- Nomes de obfuscadores/exploits
    "luraph", "psu", "ironbrew", "synapse", "krnl", "oxygen", 
    "jjsploit", "delta", "sentinel", "protosmasher",
    
    -- Termos técnicos
    "encrypt", "decrypt", "encode", "decode", "obfuscate", "deobfuscate",
    "compile", "bytecode", "source", "binary", "ascii", "utf8",
    
    -- Roblox específico
    "roblox", "rbx", "studio", "exploit", "admin", "owner", "dev",
    "localplayer", "workspace", "game", "players", "services",
    
    -- Combinações alfanuméricas
    "abc", "xyz", "123", "abc123", "123abc", "test123", "key123",
    "admin123", "pass123", "code123", "data123"
}

-- Chaves de caracteres especiais e símbolos
CryptoKeysModule.SymbolKeys = {
    -- Símbolos básicos
    "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=",
    "[", "]", "{", "}", "|", "\\", ":", ";", "'", "\"", "<", ">", ",", ".", "?", "/",
    
    -- Combinações de símbolos
    "!@#", "$%^", "&*(", ")_+", "=-[]", "{}|\\", ":;'\"", "<>,.?/",
    
    -- Espaços e caracteres de controle
    " ", "\t", "\n", "\r",
    
    -- ASCII especiais (códigos de caracteres)
    string.char(0), string.char(1), string.char(2), string.char(127),
    string.char(255), string.char(128), string.char(64), string.char(32)
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
    "ZGVsdGE="      -- delta
}

-- Chaves de deslocamento (shift) para Caesar cipher
CryptoKeysModule.ShiftKeys = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17, -18, -19, -20, -21, -22, -23, -24, -25
}

-- Chaves XOR específicas (mais usadas)
CryptoKeysModule.XorKeys = {
    -- Chaves single-byte
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    
    -- Chaves específicas comuns
    42, 69, 123, 255, 127, 63, 31, 15, 7, 3,
    
    -- Chaves multi-byte (como arrays)
    {0x12, 0x34}, {0xAB, 0xCD}, {0xFF, 0x00}, {0x00, 0xFF},
    {0x12, 0x34, 0x56}, {0xAB, 0xCD, 0xEF}, {0x11, 0x22, 0x33},
    {0x01, 0x02, 0x03, 0x04}, {0xFF, 0xFE, 0xFD, 0xFC}
}

-- Padrões de chaves usados em diferentes obfuscadores
CryptoKeysModule.ObfuscatorKeys = {
    -- Luraph
    luraph = {
        numeric = {1337, 2021, 123456, 0xDEADBEEF},
        strings = {"luraph", "obf", "protected", "anti"},
        patterns = {"^luraph_", "_obf$", "protected_"}
    },
    
    -- PSU
    psu = {
        numeric = {69, 420, 1234, 5678},
        strings = {"psu", "getfenv", "setfenv", "env"},
        patterns = {"psu_", "_env", "getfenv_"}
    },
    
    -- IronBrew
    ironbrew = {
        numeric = {32, 64, 128, 256},
        strings = {"ironbrew", "bit32", "bxor", "rshift"},
        patterns = {"ib_", "_bit", "brew_"}
    },
    
    -- Synapse
    synapse = {
        numeric = {777, 1337, 9999},
        strings = {"syn", "synapse", "crypt", "secure"},
        patterns = {"syn_", "_crypt", "secure_"}
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

-- Log de carregamento
print("🔑 CryptoKeysModule v" .. CryptoKeysModule.Info.Version .. " carregado!")
print("📊 Total de chaves disponíveis: " .. CryptoKeysModule:CountKeys())
print("🎯 Pronto para quebra de criptografia!")

return CryptoKeysModule
