using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Tools
{
    internal class Serialization
    {
        /*
        public static HugeMemoryStream SerializeConcurrentDictionary(ConcurrentDictionary<byte[], int> dict)
        {
            HugeMemoryStream stream = new HugeMemoryStream();
            DataContractSerializer serializer = new DataContractSerializer(typeof(ConcurrentDictionary<byte[], int>));
            serializer.WriteObject(stream, dict);
            stream.Seek(0, SeekOrigin.Begin);
            return stream;
        }

        public static ConcurrentDictionary<byte[], int> DeserializeConcurrentDictionary(HugeMemoryStream stream)
        {
            DataContractSerializer serializer = new DataContractSerializer(typeof(ConcurrentDictionary<byte[], int>));
            return (ConcurrentDictionary<byte[], int>)serializer.ReadObject(stream);
        }
        */


        // 将ConcurrentDictionary对象序列化到HugeMemoryStream中
        public static HugeMemoryStream SerializeConcurrentDictionary(Dictionary<byte[], int> dict)
        {
            HugeMemoryStream memoryStream = new HugeMemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(memoryStream, dict.ToArray());
            memoryStream.Position = 0;
            return memoryStream;
        }

        // 将HugeMemoryStream对象反序列化为ConcurrentDictionary对象
        public static Dictionary<byte[], int> DeserializeConcurrentDictionary(HugeMemoryStream stream)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            stream.Position = 0; // 重置流的初始位置
            var array = (KeyValuePair<byte[], int>[])formatter.Deserialize(stream);
            var dict = new Dictionary<byte[], int>();
            foreach (var kvp in array)
            {
                dict.TryAdd(kvp.Key, kvp.Value);
            }
            return dict;
        }



        public static byte[] Serialize<T>(T obj)
        {
            if (obj == null)
                return null;

            string json = JsonConvert.SerializeObject(obj);
            return System.Text.Encoding.UTF8.GetBytes(json);
        }

        public static T Deserialize<T>(byte[] bytes)
        {
            if (bytes == null)
                return default(T);

            string json = System.Text.Encoding.UTF8.GetString(bytes);
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}
