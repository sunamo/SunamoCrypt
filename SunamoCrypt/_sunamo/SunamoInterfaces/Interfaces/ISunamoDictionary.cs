// variables names: ok
namespace SunamoCrypt._sunamo.SunamoInterfaces.Interfaces;

internal interface ISunamoDictionary<T, U>
{
    U this[T key] { get; set; }
    ICollection<T> Keys { get; }
    ICollection<U> Values { get; }
    int Count { get; }
    bool IsReadOnly { get; }
    void Add(T key, U value);
    void Add(KeyValuePair<T, U> keyValue);
    void Clear();
    bool Contains(KeyValuePair<T, U> keyValue);
    bool ContainsKey(T key);
    void CopyTo(KeyValuePair<T, U>[] array, int arrayIndex);
    IEnumerator<KeyValuePair<T, U>> GetEnumerator();
    bool Remove(T key);
    bool Remove(KeyValuePair<T, U> keyValue);
    bool TryGetValue(T key, out U value);
}