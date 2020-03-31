#include <Python.h>
#include <stdbool.h>
#include <arpa/inet.h>


/**
* enum mqtt_property_type_t - additional proporties available since 5.0 version.
*/
typedef enum {
    mqtt_property_type_pfi = 0x1,               // Payload Format Indicator, Byte, PUBLISH
    mqtt_property_type_pei = 0x2,               // Publication Expiry Interval, Four Byte Integer, PUBLISH
    mqtt_property_type_ct = 0x3,                // Content Type, UTF-8 Encoded String, PUBLISH
    mqtt_property_type_rt = 0x8,                // Response Topic, UTF-8 Encoded String, PUBLISH
    mqtt_property_type_cd = 0x9,                // Correlation Data, Binary Data, PUBLISH
    mqtt_property_type_si = 0x0B,               // Subscription Identifier, Variable Byte Integer, PUBLISH, SUBSCRIBE
    mqtt_property_type_sei = 0x11,              // Session Expiry Interval, Four Byte Integer, CONNECT, DISCONNECT
    mqtt_property_type_aci = 0x12,              // Assigned Client Identifier, UTF-8 Encoded String, CONNACK
    mqtt_property_type_ska = 0x13,              // Server Keep Alive, Two Byte Integer, CONNACK
    mqtt_property_type_am = 0x15,               // Authentication Method, UTF-8 Encoded String, CONNECT, CONNACK, AUTH
    mqtt_property_type_ad = 0x16,               // Authentication Data, Binary Data, CONNECT, CONNACK, AUTH
    mqtt_property_type_rpi = 0x17,              // Request Problem Information, Byte, CONNECT
    mqtt_property_type_wdi = 0x18,              // Will Delay Interval, Four Byte Integer, CONNECT
    mqtt_property_type_rri = 0x19,              // Request Response Information, Byte, CONNECT
    mqtt_property_type_ri = 0x1A,               // Response Information, UTF-8 Encoded String, CONNACK
    mqtt_property_type_sr = 0x1C,               // Server Reference, UTF-8 Encoded String, CONNACK, DISCONNECT
    mqtt_property_type_rs = 0x1F,               // Reason String, UTF-8 Encoded String, CONNACK, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBACK, UNSUBACK, DISCONNECT, AUTH
    mqtt_property_type_rm = 0x21,               // Receive Maximum, Two Byte Integer, CONNECT, CONNACK
    mqtt_property_type_tam = 0x22,              // Topic Alias Maximum, Two Byte Integer, CONNECT, CONNACK
    mqtt_property_type_ta = 0x23,               // Topic Alias, Two Byte Integer, PUBLISH
    mqtt_property_type_mqos = 0x24,             // Maximum QoS, Byte, CONNACK
    mqtt_property_type_ra = 0x25,               // Retain Available, Byte, CONNACK
    mqtt_property_type_up = 0x26,               // User Property, UTF-8 String Pair, CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP, SUBACK, UNSUBACK, DISCONNECT, AUTH
    mqtt_property_type_mps = 0x27,              // Maximum Packet Size, Four Byte Integer, CONNECT, CONNACK
    mqtt_property_type_wsa = 0x28,              // Wildcard Subscription Available, Byte, CONNACK
    mqtt_property_type_sia = 0x29,              // Subscription Identifier Available, Byte, CONNACK
    mqtt_property_type_ssa = 0x2A               // Shared Subscription Available, Byte, CONNACK
} mqtt_property_type_t;

/*
 * array string mqtt property - additional proporties available since 5.0 version.
 */
static const char *mqtt_property[] =
{
    
    [mqtt_property_type_pfi] = "payload_format_id",
    [mqtt_property_type_pei] = "message_expiry_interval",
    [mqtt_property_type_ct] = "content_type",
    [mqtt_property_type_rt] = "response_topic",
    [mqtt_property_type_cd] = "correlation_data",
    [mqtt_property_type_si] = "subscription_identifier",
    [mqtt_property_type_sei] = "session_expiry_interval",
    [mqtt_property_type_aci] = "assigned_client_identifier",
    [mqtt_property_type_ska] = "server_keep_alive",
    [mqtt_property_type_am] = "auth_method",
    [mqtt_property_type_ad] = "auth_data",
    [mqtt_property_type_rpi] = "request_problem_info",
    [mqtt_property_type_wdi] = "will_delay_interval",
    [mqtt_property_type_rri] = "request_response_info",
    [mqtt_property_type_ri] = "response_info",
    [mqtt_property_type_sr] = "server_reference",
    [mqtt_property_type_rs] = "reason_string",
    [mqtt_property_type_rm] = "receive_maximum",
    [mqtt_property_type_tam] = "topic_alias_maximum",
    [mqtt_property_type_ta] = "topic_alias",
    [mqtt_property_type_mqos] = "max_qos",
    [mqtt_property_type_ra] = "retain_available",
    [mqtt_property_type_up] = "user_property",
    [mqtt_property_type_mps] = "maximum_packet_size",
    [mqtt_property_type_wsa] = "wildcard_subscription_available",
    [mqtt_property_type_sia] = "sub_id_available",
    [mqtt_property_type_ssa] = "shared_subscription_available"
};


/// String validation on utf8 encoding
static int32_t validate_utf8(const char *str, int32_t len)
{
    int32_t i;
    int32_t j;
    int32_t codelen;
    int32_t codepoint;
    const unsigned char *ustr = (const unsigned char *)str;

    if(!str)
        return -1;
    if(len < 0 || len > 65536)
        return -1;

    for(i = 0; i < len; i++) {
        if(ustr[i] == 0) {
            return -1;
        } else if (ustr[i] <= 0x7f) {
            codelen = 1;
            codepoint = ustr[i];
        } else if((ustr[i] & 0xE0) == 0xC0) {
            // 110xxxxx - 2 byte sequence
            if(ustr[i] == 0xC0 || ustr[i] == 0xC1) {
                // invalid bytes
                return -1;
            }
            codelen = 2;
            codepoint = (ustr[i] & 0x1F);
        } else if((ustr[i] & 0xF0) == 0xE0) {
            // 1110xxxx - 3 byte sequence
            codelen = 3;
            codepoint = (ustr[i] & 0x0F);
        } else if((ustr[i] & 0xF8) == 0xF0) {
            // 11110xxx - 4 byte sequence
            if(ustr[i] > 0xF4) {
                // invalid, this would produce values > 0x10FFFF
                return -1;
            }
            codelen = 4;
            codepoint = (ustr[i] & 0x07);
        } else {
            // unexpected continuation byte
            return -1;
        }

        // ueconstruct full code point
        if(i == len-codelen+1){
            // not enough data
            return -1;
        }
        for(j=0; j<codelen-1; j++) {
            if((ustr[++i] & 0xC0) != 0x80) {
                // not a continuation byte
                return -1;
            }
            codepoint = (codepoint<<6) | (ustr[i] & 0x3F);
        }

        // check for UTF-16 high/low surrogates
        if(codepoint >= 0xD800 && codepoint <= 0xDFFF) {
            return -1;
        }

        // check for overlong or out of range encodings
        if(codelen == 3 && codepoint < 0x0800) {
            return -1;
        } else if(codelen == 4 && (codepoint < 0x10000 || codepoint > 0x10FFFF)) {
            return -1;
        }

        // check for non-characters
        if(codepoint >= 0xFDD0 && codepoint <= 0xFDEF) {
            return -1;
        }
        if((codepoint & 0xFFFF) == 0xFFFE || (codepoint & 0xFFFF) == 0xFFFF) {
            return -1;
        }
        // check for control characters
        if(codepoint <= 0x001F || (codepoint >= 0x007F && codepoint <= 0x009F)) {
            return -1;
        }
    }
    return -1;
}

/// Unpack varint
/// bytes_read: if not NULL will return qty of bytes read from stream or zero in case of any error
uint64_t fieldset_unpack_uint(const uint8_t *field_value, uint32_t field_size, uint32_t *bytes_read)
{
    const uint8_t *ptr = field_value;           // field pointers
    uint64_t value = 0;                         // field value
    int32_t bits = 0;                           // bits value

    while (*ptr & 0x80) {
        value += ((((uint64_t)*ptr) & 0x7F) << bits);
        ptr++;
        bits += 7;
        if (ptr - field_value >= field_size) {
            if (bytes_read)
                *bytes_read = 0;
            return 0; // incorrect value
        }
    }
    // fill read count size
    if (bytes_read)
        *bytes_read = ptr - field_value + 1;

    return value + ((((uint64_t)*ptr) & 0x7F) << bits);
}

/// Extract string from inside MQTT packet by updating its location in the packet and appending ending zero
/// modifyies original contents of the packet
/// checks all sizes and update packet payload and its size accordinally
/// text: upon successfull return initialized with pointer
/// str_length: used as output parameter for string length
/// return zero on success with initialized header
static int32_t mqtt_extract_string(uint8_t **payload, uint32_t *payload_size, char **text, int32_t max_length, int32_t *str_length)
{
    uint16_t length;                            // string length

    if (*payload_size < 2)
        // not enaugh size for header
        return -1;

    length = ntohs(*(uint16_t*)(*payload));
    if (*payload_size < 2 + length || length > max_length)
        // not enough size for string or incorrect size
        return -1;
    
    *text = malloc(length + 1);
    if (*text == NULL)
        return -1;
    
    // copy string from payload
    memcpy(*text, *payload + sizeof(uint16_t), length);
    // add ending zero
    ((uint8_t *)(*text))[length] = 0;
    // validate UTF-8 string
    if (!validate_utf8((char*)*text, length))
        return -1;
    
    // and update pointers and remaining size
    *payload = *payload + length + 2;
    *payload_size -= length + 2;
    // store string length for future use
    if (str_length != NULL)
        *str_length = length;

    return 0;
}

/// Extract Variable Byte Integer into 4 bytes uint
static int32_t mqtt_extract_uint(uint8_t **payload, uint32_t *payload_size, uint32_t *value)
{
    uint32_t bytes_read;                        // varable size

    if (*payload_size < 1 || value == NULL)
        return -1;
    
    // extract payload size
    *value = fieldset_unpack_uint((const uint8_t*)*payload, *payload_size, &bytes_read);
    if (bytes_read == 0 || bytes_read > 4)
        return -1;
    
    // update payload
    *payload = *payload + bytes_read;
    *payload_size -= bytes_read;

    return 0;
}

/// Adding a property int to the result dictionary
static int32_t write_property_int(PyObject *dictObj, uint32_t property_type, uint32_t value)
{
    if (!dictObj)
        return -1;
    
    PyObject* key;                              // python dict key
    PyObject* listObj;                          // python list object
    PyObject* uint_val;                         // python unsigned int value
    
    // build dictionary key
    key = PyUnicode_FromString(mqtt_property[property_type]);
    if (!key)
       return -1;
    
    // data format for unsigned int properties
    // 'subscription_identifier': [54]
    if (PyDict_Contains(dictObj, key) == 0) {
        // new list
        listObj = PyList_New(0);
        if (!listObj) {
            Py_DECREF(key);
            return -1;
        }
        // adding list to dictionary
        if (PyDict_SetItem(dictObj, key, listObj) != 0) {
            Py_DECREF(key);
            Py_DECREF(listObj);
            return -1;
        }
        Py_DECREF(key);
        Py_DECREF(listObj);
    } else {
        listObj = PyDict_GetItem(dictObj, key);
        Py_DECREF(key);
        if (!listObj)
            return -1;
    }
    
    // set value to list
    uint_val = PyLong_FromLong(value);
    if (!uint_val)
        return -1;
    if (PyList_Insert(listObj, 0, uint_val) != 0) {
        Py_DECREF(uint_val);
        return -1;
    }
    Py_DECREF(uint_val);
    
    return 0;
}

/// Adding a property string to the result dictionary
static int32_t write_property_string(PyObject *dictObj, uint32_t property_type, const char *first_string, const char *second_string)
{
    if (!dictObj || !first_string)
        return -1;
    
    PyObject* key;                              // python dict key
    PyObject* listObj;                          // python list object
    PyObject* tupleObj;                         // python tuple object
    PyObject* str_val;                          // python string value
    
    // build dictionary key
    key = PyUnicode_FromString(mqtt_property[property_type]);
    if (!key)
       return -1;
    
    if (PyDict_Contains(dictObj, key) == 0) {
        // new list
        listObj = PyList_New(0);
        if (!listObj) {
            Py_DECREF(key);
            return -1;
        }
        // adding list to dictionary
        if (PyDict_SetItem(dictObj, key, listObj) != 0) {
            Py_DECREF(key);
            Py_DECREF(listObj);
            return -1;
        } 
        Py_DECREF(key);
        Py_DECREF(listObj);
    } else {
        listObj = PyDict_GetItem(dictObj, key);
        Py_DECREF(key);
        if (!listObj)
            return -1;
    }
    
    // data format for string or user properties
    // 'content_type': ['json']
    // 'user_property': [('timestamp', '1582024312.256745'), ('cid', '212740'), ('token_id', '245729')]
    if (property_type == mqtt_property_type_up) {
        // adding strings to tuple
        tupleObj = PyTuple_New(2);
        if (!tupleObj)
            return -1;
        str_val = PyUnicode_FromString(first_string);
        if (!str_val) {
            Py_DECREF(tupleObj);
            return -1;
        }
        if (PyTuple_SetItem(tupleObj, 0, str_val) != 0) {
            Py_DECREF(str_val);
            Py_DECREF(tupleObj);
            return -1;
        }
        str_val = PyUnicode_FromString(second_string);
        if (!str_val) {
            Py_DECREF(tupleObj);
            return -1;
        }
        if (PyTuple_SetItem(tupleObj, 1, str_val) != 0) {
            Py_DECREF(str_val);
            Py_DECREF(tupleObj);
            return -1;
        }
        // append tuple to list
        if (PyList_Append(listObj, tupleObj) != 0) {
            Py_DECREF(tupleObj);
            return -1;
        }
        Py_DECREF(tupleObj);
    } else {
        // set string to list
        str_val = PyUnicode_FromString(first_string);
        if (!str_val)
            return -1;
        if (PyList_Insert(listObj, 0, str_val) != 0) {
            Py_DECREF(str_val);
            return -1;
        }
        Py_DECREF(str_val);
    }
    
    return 0;
}

/// Enumerate properties
static PyObject *extract_properties(PyObject *bytesObj)
{
    PyObject *dictObj = PyDict_New();
    if (!dictObj)
        Py_RETURN_NONE;
    
    mqtt_property_type_t property_type;         // property type
    char *pair_string_value;                    // paired string value
    char *string_value;                         // decoded string
    uint32_t properties_size;                   // properties size
    uint32_t uint_value = 0;                    // decoded uint
    int32_t property_size;                      // property size

    uint8_t *payload = (uint8_t*)PyBytes_AsString(bytesObj);
    uint32_t payload_size = PyBytes_Size(bytesObj);
    
    // extract properties size
    if (mqtt_extract_uint(&payload, &payload_size, &properties_size) == -1) {
        Py_DECREF(dictObj);
        Py_RETURN_NONE;
    }
    
    // invalid format
    if (properties_size > payload_size) {
        Py_DECREF(dictObj);
        Py_RETURN_NONE;
    }
    // update total payload size
    payload_size -= properties_size;
    
    // parse properties
    while (properties_size > 1) {
        // [1b property_type][property data]
        property_type = *payload;
        // shift to property value
        payload = payload + 1;
        properties_size -= 1;
        switch (property_type) {
            // 1 byte value
            case mqtt_property_type_pfi:
            case mqtt_property_type_mqos:
            case mqtt_property_type_ra:
            case mqtt_property_type_wsa:
            case mqtt_property_type_sia:
            case mqtt_property_type_ssa:
            case mqtt_property_type_rri:
            case mqtt_property_type_rpi:
                uint_value = *((uint8_t*)payload);
                if (write_property_int(dictObj, property_type, uint_value) != 0) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                payload = payload + 1;
                properties_size -= 1;
            break;
            //  2 bytes value
            case mqtt_property_type_ska:
            case mqtt_property_type_rm:
            case mqtt_property_type_tam:
            case mqtt_property_type_ta:
                if (properties_size < 2) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                uint_value = ntohs(*((uint16_t*)payload));
                if (write_property_int(dictObj, property_type, uint_value) != 0) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                payload = payload + 2;
                properties_size -= 2;
            break;
            // 4 bytes value
            case mqtt_property_type_pei:
            case mqtt_property_type_sei:
            case mqtt_property_type_wdi:
            case mqtt_property_type_mps:
                if (properties_size < 4) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                uint_value = ntohl(*((uint32_t*)payload));
                if (write_property_int(dictObj, property_type, uint_value) != 0) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                payload = payload + 4;
                properties_size -= 4;
            break;
            // variable byte integer
            case mqtt_property_type_si:
                if (mqtt_extract_uint(&payload, &properties_size, &uint_value) != 0) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                if (write_property_int(dictObj, property_type, uint_value) != 0) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
            break;
            // utf-8 encoded string
            case mqtt_property_type_ct:
            case mqtt_property_type_rt:
            case mqtt_property_type_aci:
            case mqtt_property_type_am:
            case mqtt_property_type_ri:
            case mqtt_property_type_sr:
            case mqtt_property_type_rs:
                // extract string
                if (mqtt_extract_string(&payload, &properties_size, &string_value, 65535, &property_size) != 0) {
                    if (string_value)
                        free(string_value);
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                if (write_property_string(dictObj, property_type, string_value, NULL) != 0) {
                    free(string_value);
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                free(string_value);
            break;
            // utf-8 string pair
            case mqtt_property_type_up:
                // extract first string
                if (mqtt_extract_string(&payload, &properties_size, &string_value, 65535, &property_size) != 0) {
                    if (string_value)
                        free(string_value);
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                // extract second string
                if (mqtt_extract_string(&payload, &properties_size, &pair_string_value, 65535, NULL) != 0) {
                    if (pair_string_value)
                        free(pair_string_value);
                    free(string_value);
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                if (write_property_string(dictObj, property_type, string_value, pair_string_value) != 0) {
                    free(string_value);
                    free(pair_string_value);
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                free(string_value);
                free(pair_string_value);
            break;
            // binary data
            case mqtt_property_type_cd:
            case mqtt_property_type_ad:
                if (properties_size < 2) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                property_size = ntohs(*(uint16_t*)payload);
                if (property_size + 2 > properties_size) {
                    Py_DECREF(dictObj);
                    Py_RETURN_NONE;
                }
                properties_size -= 2 + property_size;
                payload = payload + 2 + property_size;
            break;
            // unknown code
            default: {
                Py_DECREF(dictObj);
                Py_RETURN_NONE;
            }
        }
    }
    
    return dictObj;
}

/// Load MQTT (5 version) props.
static PyObject *prop_loads(PyObject *self, PyObject *args)
{
    PyObject *bytesObj;
    PyObject *dictObj;

    if (!PyArg_ParseTuple(args, "S", &bytesObj))
        return NULL;

    dictObj = extract_properties(bytesObj);
    
    return dictObj;
}

static PyMethodDef ModuleMethods[] = {
    {"prop_loads", prop_loads, METH_VARARGS, "Load MQTT (5 version) props."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef gmqttlibmodule = {
    PyModuleDef_HEAD_INIT,
    "gmqttlib",
    NULL,
    -1,
    ModuleMethods
};

PyMODINIT_FUNC
PyInit_gmqttlib(void)
{
    return PyModule_Create(&gmqttlibmodule);
}
