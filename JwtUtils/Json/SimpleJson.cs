using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Text;

namespace JwtUtils.Json;

internal static class SimpleJson
{
    public static string Serialize(object obj)
    {
        if (obj == null)
            return "null";

        var sb = new StringBuilder();
        SerializeValue(obj, sb);
        return sb.ToString();
    }

    public static T Deserialize<T>(ReadOnlySpan<char> json)
    {
        var parser = new JsonParser(json);
        var value = parser.ParseValue();
        return (T)ConvertValue(value, typeof(T));
    }

    public static T Deserialize<T>(string json)
    {
        return Deserialize<T>(json.AsSpan());
    }

    private static void SerializeValue(object obj, StringBuilder sb)
    {
        if (obj == null)
        {
            sb.Append("null");
            return;
        }

        var type = obj.GetType();

        if (type == typeof(string))
        {
            SerializeString((string)obj, sb);
        }
        else if (type == typeof(bool))
        {
            sb.Append(((bool)obj) ? "true" : "false");
        }
        else if (IsNumericType(type))
        {
            SerializeNumber(obj, sb);
        }
        else if (type == typeof(DateTime))
        {
            var dt = (DateTime)obj;
            SerializeString(dt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture), sb);
        }
        else if (obj is IDictionary dict)
        {
            SerializeDictionary(dict, sb);
        }
        else if (obj is IEnumerable enumerable && type != typeof(string))
        {
            SerializeArray(enumerable, sb);
        }
        else
        {
            SerializeObject(obj, sb);
        }
    }

    private static void SerializeString(string str, StringBuilder sb)
    {
        sb.Append('"');
        foreach (char c in str)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (c < ' ')
                    {
                        sb.Append("\\u");
                        sb.Append(((int)c).ToString("x4"));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    private static void SerializeNumber(object obj, StringBuilder sb)
    {
        if (obj is float f)
            sb.Append(f.ToString("R", CultureInfo.InvariantCulture));
        else if (obj is double d)
            sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
        else if (obj is decimal dec)
            sb.Append(dec.ToString(CultureInfo.InvariantCulture));
        else
            sb.Append(obj.ToString());
    }

    private static void SerializeDictionary(IDictionary dict, StringBuilder sb)
    {
        sb.Append('{');
        bool first = true;
        foreach (DictionaryEntry entry in dict)
        {
            if (!first)
                sb.Append(',');
            first = false;

            SerializeString(entry.Key.ToString(), sb);
            sb.Append(':');
            SerializeValue(entry.Value, sb);
        }
        sb.Append('}');
    }

    private static void SerializeArray(IEnumerable enumerable, StringBuilder sb)
    {
        sb.Append('[');
        bool first = true;
        foreach (object item in enumerable)
        {
            if (!first)
                sb.Append(',');
            first = false;
            SerializeValue(item, sb);
        }
        sb.Append(']');
    }

    private static void SerializeObject(object obj, StringBuilder sb)
    {
        sb.Append('{');
        bool first = true;
        
        var type = obj.GetType();
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        foreach (var prop in properties)
        {
            if (!prop.CanRead)
                continue;

            if (!first)
                sb.Append(',');
            first = false;

            var propName = GetJsonPropertyName(prop);
            SerializeString(propName, sb);
            sb.Append(':');
            SerializeValue(prop.GetValue(obj), sb);
        }
        
        sb.Append('}');
    }

    private static string GetJsonPropertyName(PropertyInfo prop)
    {
        // Look for JsonPropertyName attribute (simplified version)
        var attrs = prop.GetCustomAttributes(false);
        foreach (var attr in attrs)
        {
            var attrType = attr.GetType();
            if (attrType.Name == "JsonPropertyNameAttribute")
            {
                var nameProperty = attrType.GetProperty("Name");
                if (nameProperty != null)
                {
                    var name = nameProperty.GetValue(attr) as string;
                    if (!string.IsNullOrEmpty(name))
                        return name;
                }
            }
        }
        
        // Convert PascalCase to camelCase by default
        var propName = prop.Name;
        if (propName.Length > 0)
        {
            return char.ToLowerInvariant(propName[0]) + propName.Substring(1);
        }
        return propName;
    }

    private static bool IsNumericType(Type type)
    {
        return type == typeof(int) || type == typeof(long) || type == typeof(short) ||
               type == typeof(uint) || type == typeof(ulong) || type == typeof(ushort) ||
               type == typeof(byte) || type == typeof(sbyte) ||
               type == typeof(float) || type == typeof(double) || type == typeof(decimal);
    }

    private static object ConvertValue(object value, Type targetType)
    {
        if (value == null)
            return targetType.IsValueType ? Activator.CreateInstance(targetType) : null;

        if (targetType.IsAssignableFrom(value.GetType()))
            return value;

        // Handle nullable types
        var nullableType = Nullable.GetUnderlyingType(targetType);
        if (nullableType != null)
        {
            if (value == null)
                return null;
            return ConvertValue(value, nullableType);
        }

        // Handle Dictionary<string, object>
        if (targetType == typeof(Dictionary<string, object>) && value is Dictionary<string, object>)
            return value;

        // Handle specific conversions
        if (targetType == typeof(string))
            return value.ToString();

        if (targetType == typeof(bool) && value is string strBool)
            return bool.Parse(strBool);

        if (IsNumericType(targetType))
            return ConvertNumber(value, targetType);

        if (targetType == typeof(DateTime) && value is string strDate)
            return DateTime.Parse(strDate, CultureInfo.InvariantCulture);

        // Handle object deserialization
        if (value is Dictionary<string, object> dict)
            return DeserializeObject(dict, targetType);

        return value;
    }

    private static object ConvertNumber(object value, Type targetType)
    {
        if (value is long l)
        {
            if (targetType == typeof(int)) return (int)l;
            if (targetType == typeof(short)) return (short)l;
            if (targetType == typeof(byte)) return (byte)l;
            if (targetType == typeof(uint)) return (uint)l;
            if (targetType == typeof(ulong)) return (ulong)l;
            if (targetType == typeof(ushort)) return (ushort)l;
            if (targetType == typeof(sbyte)) return (sbyte)l;
            if (targetType == typeof(float)) return (float)l;
            if (targetType == typeof(double)) return (double)l;
            if (targetType == typeof(decimal)) return (decimal)l;
            return l;
        }

        if (value is double d)
        {
            if (targetType == typeof(float)) return (float)d;
            if (targetType == typeof(decimal)) return (decimal)d;
            return d;
        }

        return Convert.ChangeType(value, targetType, CultureInfo.InvariantCulture);
    }

    private static object DeserializeObject(Dictionary<string, object> dict, Type targetType)
    {
        var instance = Activator.CreateInstance(targetType);
        var properties = targetType.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        foreach (var prop in properties)
        {
            if (!prop.CanWrite)
                continue;

            var jsonName = GetJsonPropertyName(prop);
            
            // Try exact match first, then case-insensitive
            object propValue = null;
            if (dict.TryGetValue(jsonName, out propValue) || 
                dict.TryGetValue(prop.Name, out propValue))
            {
                var convertedValue = ConvertValue(propValue, prop.PropertyType);
                prop.SetValue(instance, convertedValue);
            }
        }

        return instance;
    }
}

/// <summary>
/// Simple JSON parser
/// </summary>
internal ref struct JsonParser
{
    private readonly ReadOnlySpan<char> _json;
    private int _position;

    public JsonParser(ReadOnlySpan<char> json)
    {
        _json = json;
        _position = 0;
    }

    public object ParseValue()
    {
        SkipWhitespace();
        
        if (_position >= _json.Length)
            return null;

        char c = _json[_position];
        
        return c switch
        {
            '"' => ParseString(),
            '{' => ParseObject(),
            '[' => ParseArray(),
            't' or 'f' => ParseBoolean(),
            'n' => ParseNull(),
            _ when char.IsDigit(c) || c == '-' => ParseNumber(),
            _ => throw new FormatException($"Unexpected character '{c}' at position {_position}")
        };
    }

    private string ParseString()
    {
        if (_json[_position] != '"')
            throw new FormatException("Expected '\"'");

        _position++; // Skip opening quote
        var start = _position;
        var sb = new StringBuilder();

        while (_position < _json.Length)
        {
            char c = _json[_position];
            
            if (c == '"')
            {
                _position++; // Skip closing quote
                return sb.ToString();
            }
            
            if (c == '\\')
            {
                _position++;
                if (_position >= _json.Length)
                    throw new FormatException("Unterminated string escape");

                char escaped = _json[_position];
                switch (escaped)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        _position++;
                        var hex = _json.Slice(_position, 4);
                        if (hex.Length < 4)
                            throw new FormatException("Invalid unicode escape");
                        sb.Append((char)int.Parse(hex, NumberStyles.HexNumber));
                        _position += 3; // Will be incremented at end of loop
                        break;
                    default:
                        throw new FormatException($"Invalid escape sequence '\\{escaped}'");
                }
            }
            else
            {
                sb.Append(c);
            }
            
            _position++;
        }

        throw new FormatException("Unterminated string");
    }

    private Dictionary<string, object> ParseObject()
    {
        if (_json[_position] != '{')
            throw new FormatException("Expected '{'");

        _position++; // Skip opening brace
        var dict = new Dictionary<string, object>();

        SkipWhitespace();
        
        if (_position < _json.Length && _json[_position] == '}')
        {
            _position++; // Skip closing brace
            return dict;
        }

        while (_position < _json.Length)
        {
            SkipWhitespace();
            
            // Parse key
            var key = ParseString();
            
            SkipWhitespace();
            
            if (_position >= _json.Length || _json[_position] != ':')
                throw new FormatException("Expected ':'");
            
            _position++; // Skip colon
            
            // Parse value
            var value = ParseValue();
            dict[key] = value;
            
            SkipWhitespace();
            
            if (_position >= _json.Length)
                throw new FormatException("Expected '}' or ','");
            
            if (_json[_position] == '}')
            {
                _position++; // Skip closing brace
                return dict;
            }
            
            if (_json[_position] == ',')
            {
                _position++; // Skip comma
                continue;
            }
            
            throw new FormatException("Expected '}' or ','");
        }

        throw new FormatException("Unterminated object");
    }

    private object[] ParseArray()
    {
        if (_json[_position] != '[')
            throw new FormatException("Expected '['");

        _position++; // Skip opening bracket
        var items = new List<object>();

        SkipWhitespace();
        
        if (_position < _json.Length && _json[_position] == ']')
        {
            _position++; // Skip closing bracket
            return items.ToArray();
        }

        while (_position < _json.Length)
        {
            var value = ParseValue();
            items.Add(value);
            
            SkipWhitespace();
            
            if (_position >= _json.Length)
                throw new FormatException("Expected ']' or ','");
            
            if (_json[_position] == ']')
            {
                _position++; // Skip closing bracket
                return items.ToArray();
            }
            
            if (_json[_position] == ',')
            {
                _position++; // Skip comma
                SkipWhitespace();
                continue;
            }
            
            throw new FormatException("Expected ']' or ','");
        }

        throw new FormatException("Unterminated array");
    }

    private bool ParseBoolean()
    {
        if (_json.Slice(_position).StartsWith("true".AsSpan()))
        {
            _position += 4;
            return true;
        }
        
        if (_json.Slice(_position).StartsWith("false".AsSpan()))
        {
            _position += 5;
            return false;
        }
        
        throw new FormatException("Invalid boolean value");
    }

    private object ParseNull()
    {
        if (_json.Slice(_position).StartsWith("null".AsSpan()))
        {
            _position += 4;
            return null;
        }
        
        throw new FormatException("Invalid null value");
    }

    private object ParseNumber()
    {
        var start = _position;
        bool isFloat = false;

        // Handle negative sign
        if (_json[_position] == '-')
            _position++;

        // Parse integer part
        while (_position < _json.Length && char.IsDigit(_json[_position]))
            _position++;

        // Parse decimal part
        if (_position < _json.Length && _json[_position] == '.')
        {
            isFloat = true;
            _position++;
            while (_position < _json.Length && char.IsDigit(_json[_position]))
                _position++;
        }

        // Parse exponent part
        if (_position < _json.Length && (_json[_position] == 'e' || _json[_position] == 'E'))
        {
            isFloat = true;
            _position++;
            if (_position < _json.Length && (_json[_position] == '+' || _json[_position] == '-'))
                _position++;
            while (_position < _json.Length && char.IsDigit(_json[_position]))
                _position++;
        }

        var numberStr = _json.Slice(start, _position - start);

        if (isFloat)
        {
            if (double.TryParse(numberStr, NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
                return d;
        }
        else
        {
            if (long.TryParse(numberStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out long l))
                return l;
        }

        throw new FormatException($"Invalid number format: {numberStr.ToString()}");
    }

    private void SkipWhitespace()
    {
        while (_position < _json.Length && char.IsWhiteSpace(_json[_position]))
            _position++;
    }
}