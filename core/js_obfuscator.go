package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

type JSObfuscator struct {
	varNames    map[string]string
	stringTable map[string]string
	counterVar  int
	counterStr  int
}

// NewJSObfuscator creates a new JavaScript obfuscator
func NewJSObfuscator() *JSObfuscator {
	return &JSObfuscator{
		varNames:    make(map[string]string),
		stringTable: make(map[string]string),
		counterVar:  0,
		counterStr:  0,
	}
}

// Obfuscate obfuscates JavaScript code
func (jso *JSObfuscator) Obfuscate(code string) string {
	// Apply obfuscation techniques in sequence
	code = jso.addDeadCode(code)
	code = jso.obfuscateStrings(code)
	code = jso.renameVariables(code)
	code = jso.addAntiDebug(code)
	code = jso.splitStrings(code)
	code = jso.encodeNumbers(code)

	return code
}

// Generate random variable name
func (jso *JSObfuscator) randomVarName() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	length := 8
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[num.Int64()]
	}

	return string(result)
}

// Add dead code to confuse analysis
func (jso *JSObfuscator) addDeadCode(code string) string {
	deadCode := []string{
		"var _0x" + jso.randomVarName() + " = function(){return false;};",
		"if(false){console.log('debug');}",
		"var _temp = Math.random() > 2 ? null : undefined;",
		"(function(){var x = 0; x++; x--;})();",
	}

	result := deadCode[0] + "\n"
	result += code + "\n"
	result += deadCode[1] + "\n"
	result += deadCode[2]

	return result
}

// Obfuscate string literals
func (jso *JSObfuscator) obfuscateStrings(code string) string {
	// Find all string literals
	stringPattern := regexp.MustCompile(`["']([^"'\\]*(\\.[^"'\\]*)*)["']`)

	// Replace with encoded versions
	code = stringPattern.ReplaceAllStringFunc(code, func(match string) string {
		// Remove quotes
		str := match[1 : len(match)-1]

		// Base64 encode
		encoded := base64.StdEncoding.EncodeToString([]byte(str))

		// Return as function call
		return fmt.Sprintf("atob('%s')", encoded)
	})

	return code
}

// Rename variables to obfuscated names
func (jso *JSObfuscator) renameVariables(code string) string {
	// Common JavaScript variables to rename
	varPattern := regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)

	code = varPattern.ReplaceAllStringFunc(code, func(match string) string {
		parts := strings.Split(match, " ")
		if len(parts) >= 2 {
			varType := parts[0]
			varName := parts[1]

			// Don't rename if already obfuscated or reserved
			if strings.HasPrefix(varName, "_0x") || isReservedWord(varName) {
				return match
			}

			// Generate obfuscated name
			if _, exists := jso.varNames[varName]; !exists {
				jso.varNames[varName] = "_0x" + jso.randomVarName()
			}

			return varType + " " + jso.varNames[varName]
		}
		return match
	})

	// Replace variable usages
	for original, obfuscated := range jso.varNames {
		wordBoundary := regexp.MustCompile(`\b` + original + `\b`)
		code = wordBoundary.ReplaceAllString(code, obfuscated)
	}

	return code
}

// Add anti-debugging code
func (jso *JSObfuscator) addAntiDebug(code string) string {
	antiDebug := `
(function() {
    var _0xcheck = function() {
        var _0xstart = new Date().getTime();
        debugger;
        var _0xend = new Date().getTime();
        if (_0xend - _0xstart > 100) {
            window.location.reload();
        }
    };
    setInterval(_0xcheck, 1000);
})();
`
	return antiDebug + "\n" + code
}

// Split strings to avoid pattern detection
func (jso *JSObfuscator) splitStrings(code string) string {
	// Split long strings into concatenated parts
	longStringPattern := regexp.MustCompile(`atob\('([^']{20,})'\)`)

	code = longStringPattern.ReplaceAllStringFunc(code, func(match string) string {
		// Extract the base64 string
		base64Str := match[6 : len(match)-2] // Remove atob(' and ')

		// Split into chunks
		chunkSize := 10
		var chunks []string
		for i := 0; i < len(base64Str); i += chunkSize {
			end := i + chunkSize
			if end > len(base64Str) {
				end = len(base64Str)
			}
			chunks = append(chunks, base64Str[i:end])
		}

		// Create concatenation
		if len(chunks) > 1 {
			result := "atob('"
			for i, chunk := range chunks {
				if i > 0 {
					result += "'+'"
				}
				result += chunk
			}
			result += "')"
			return result
		}

		return match
	})

	return code
}

// Encode numbers to avoid detection
func (jso *JSObfuscator) encodeNumbers(code string) string {
	numberPattern := regexp.MustCompile(`\b(\d+)\b`)

	code = numberPattern.ReplaceAllStringFunc(code, func(match string) string {
		// Don't encode very small numbers or numbers in special contexts
		if len(match) == 1 {
			return match
		}

		// Convert to hex
		num := 0
		fmt.Sscanf(match, "%d", &num)
		return fmt.Sprintf("0x%x", num)
	})

	return code
}

// Check if word is JavaScript reserved keyword
func isReservedWord(word string) bool {
	reserved := map[string]bool{
		"break": true, "case": true, "catch": true, "class": true, "const": true,
		"continue": true, "debugger": true, "default": true, "delete": true,
		"do": true, "else": true, "export": true, "extends": true, "finally": true,
		"for": true, "function": true, "if": true, "import": true, "in": true,
		"instanceof": true, "let": true, "new": true, "return": true, "super": true,
		"switch": true, "this": true, "throw": true, "try": true, "typeof": true,
		"var": true, "void": true, "while": true, "with": true, "yield": true,
		"window": true, "document": true, "console": true, "atob": true, "btoa": true,
	}
	return reserved[word]
}

// ObfuscateInlineJS obfuscates JavaScript for inline injection
func ObfuscateInlineJS(code string) string {
	obf := NewJSObfuscator()
	return obf.Obfuscate(code)
}

// CreateStealthScript creates a stealthy JavaScript payload
func CreateStealthScript(payloadFunc string) string {
	obf := NewJSObfuscator()

	wrapper := fmt.Sprintf(`
(function() {
    var _0x%s = function() {
        try {
            %s
        } catch(e) {
            // Silent fail
        }
    };
    
    if (document.readyState === 'complete') {
        _0x%s();
    } else {
        window.addEventListener('load', _0x%s);
    }
})();
`, obf.randomVarName(), payloadFunc, obf.randomVarName(), obf.randomVarName())

	return obf.Obfuscate(wrapper)
}

// Advanced obfuscation with control flow flattening
func (jso *JSObfuscator) flattenControlFlow(code string) string {
	// This would implement control flow flattening
	// For now, return code as-is (complex to implement)
	return code
}

// Encrypt strings with XOR
func (jso *JSObfuscator) xorEncryptStrings(code string) string {
	key := jso.randomVarName()[:4]

	stringPattern := regexp.MustCompile(`["']([^"']*)["']`)

	code = stringPattern.ReplaceAllStringFunc(code, func(match string) string {
		str := match[1 : len(match)-1]
		encrypted := xorString(str, key)
		encodedKey := base64.StdEncoding.EncodeToString([]byte(key))
		return fmt.Sprintf("_0xdecrypt('%s','%s')", encrypted, encodedKey)
	})

	// Add decrypt function
	decryptFunc := fmt.Sprintf(`
function _0xdecrypt(enc, key) {
    var k = atob(key);
    var result = '';
    for(var i = 0; i < enc.length; i++) {
        result += String.fromCharCode(enc.charCodeAt(i) ^ k.charCodeAt(i %% k.length));
    }
    return result;
}
`)

	return decryptFunc + code
}

// XOR helper function
func xorString(input, key string) string {
	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i] ^ key[i%len(key)]
	}
	return string(result)
}
