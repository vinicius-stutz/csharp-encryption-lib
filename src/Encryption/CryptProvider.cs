namespace Encryption
{
    /// <summary>Enumerator com os tipos de classes para criptografia.</summary>
    public enum CryptProvider
    {
        /// <summary>Representa a classe base para implementações criptografia dos algoritmos simétricos Rijndael.</summary>
        Rijndael,
        /// <summary>Representa a classe base para implementações do algoritmo RC2.</summary>
        RC2,
        /// <summary>Representa a classe base para criptografia de dados padrões (DES - Data Encryption Standard).</summary>
        DES,
        /// <summary>Representa a classe base (TripleDES - Triple Data Encryption Standard).</summary>
        TripleDES
    }
}
