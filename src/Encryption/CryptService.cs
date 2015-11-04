using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    /// <summary>
    /// <para>DLL/Classe de criptgrafia.</para>
    /// <para></para>
    /// <para>Exemplo de como usar para criptografar:</para>
    /// <para>CryptService crip = new CryptService(CryptProvider.DES);</para>
    /// <para>crip.Key = "MY KEY HERE"; // Esta chave você mesmo é quem escolhe</para>
    /// <para>return crip.Encrypt(yourString);</para>
    /// <para></para>
    /// <para>Exemplo de como usar para descriptografar:</para>
    /// <para>CryptService crip = new CryptService(CryptProvider.DES);</para>
    /// <para>crip.Key = "MY KEY HERE"; // Esta chave tem que ser a mesma do texto criptografado</para>
    /// <para>return crip.Decrypt(yourString);</para>
    /// </summary>
    public class CryptService
    {
        #region Variáveis e Métodos Privados

        private CryptProvider provider;
        private SymmetricAlgorithm algorithm;

        /// <summary>Inicialização do vetor do algoritmo simétrico</summary>
        private void SetAlgorithm()
        {
            switch (provider)
            {
                case CryptProvider.Rijndael:
                    algorithm.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9, 0x5, 0x46, 0x9c, 0xea, 0xa8, 0x4b, 0x73, 0xcc };
                    break;
                default:
                    algorithm.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 };
                    break;
            }
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------

        #region Properties

        /// <summary>Chave secreta para o algoritmo simétrico de criptografia.</summary>
        public string Key { get; set; }

        #endregion

        // ----------------------------------------------------------------------------------------------------

        #region Constructors

        /// <summary>Contrutor padrão da classe, é setado um tipo de criptografia padrão (Rijndael).</summary>
        public CryptService()
        {
            algorithm = new RijndaelManaged();
            algorithm.Mode = CipherMode.CBC;
            provider = CryptProvider.Rijndael;
        }

        /// <summary>
        /// Construtor com o tipo de criptografia a ser usada Você pode escolher o tipo pelo Enum chamado CryptProvider.
        /// </summary>
        /// <param name="cp">Tipo de criptografia.</param>
        public CryptService(CryptProvider cp)
        {
            // Seleciona algoritmo simétrico
            switch (cp)
            {
                case CryptProvider.Rijndael:
                    algorithm = new RijndaelManaged();
                    provider = CryptProvider.Rijndael;
                    break;

                case CryptProvider.RC2:
                    algorithm = new RC2CryptoServiceProvider();
                    provider = CryptProvider.RC2;
                    break;

                case CryptProvider.DES:
                    algorithm = new DESCryptoServiceProvider();
                    provider = CryptProvider.DES;
                    break;

                case CryptProvider.TripleDES:
                    algorithm = new TripleDESCryptoServiceProvider();
                    provider = CryptProvider.TripleDES;
                    break;
            }
            algorithm.Mode = CipherMode.CBC;
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------

        #region Public methods

        /// <summary>Gera a chave de criptografia válida dentro do array.</summary>
        /// <returns>Chave com array de bytes.</returns>
        public virtual byte[] GetKey(string salt)
        {
            // Ajusta o tamanho da chave se necessário e retorna uma chave válida
            if (algorithm.LegalKeySizes.Length > 0)
            {
                // Tamanho das chaves em bits
                int keySize = Key.Length * 8;
                int minSize = algorithm.LegalKeySizes[0].MinSize;
                int maxSize = algorithm.LegalKeySizes[0].MaxSize;
                int skipSize = algorithm.LegalKeySizes[0].SkipSize;

                // Busca o valor máximo da chave
                if (keySize > maxSize) { Key = Key.Substring(0, maxSize / 8); }
                else if (keySize < maxSize)
                {
                    // Define um tamanho válido
                    int validSize = (keySize <= minSize) ? minSize : (keySize - keySize % skipSize) + skipSize;
                    validSize = validSize / 8;
                    // Preenche a chave com arterisco para corrigir o tamanho
                    if (keySize < validSize) { Key = Key.PadRight(validSize, Convert.ToChar("*")); }
                }
            }
            PasswordDeriveBytes pass = new PasswordDeriveBytes(Key, ASCIIEncoding.ASCII.GetBytes(salt));
            return pass.GetBytes(Key.Length);
        }


        /// <summary>Encripta o dado solicitado.</summary>
        /// <param name="val">String a ser criptografada.</param>
        /// <returns>Texto criptografado.</returns>
        public virtual string Encrypt(string val)
        {
            byte[] plainByte = Encoding.UTF8.GetBytes(val);
            byte[] keyByte = GetKey(string.Empty);

            // Seta a chave privada
            algorithm.Key = keyByte;

            SetAlgorithm();

            // Interface de criptografia / Cria objeto de criptografia
            ICryptoTransform cryptoTransform = algorithm.CreateEncryptor();

            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write);

            // Grava os dados criptografados no MemoryStream
            cs.Write(plainByte, 0, plainByte.Length);
            cs.FlushFinalBlock();

            // Busca o tamanho dos bytes encriptados
            byte[] cryptoByte = ms.ToArray();

            // Converte para a base 64 string para uso posterior em um xml
            return Convert.ToBase64String(cryptoByte, 0, cryptoByte.GetLength(0));
        }


        /// <summary>Desencripta o dado solicitado.</summary>
        /// <param name="val">Texto a ser descriptografado.</param>
        /// <returns>Texto descriptografado.</returns>
        public virtual string Decrypt(string val)
        {

            // Em caso de "Invalid length for a Base-64 char array"
            val = val.Replace(" ", "+");
            int mod4 = val.Length % 4;
            if (mod4 > 0) val += new string('=', 4 - mod4);

            // Converte a base 64 string em num array de bytes
            byte[] cryptoByte = Convert.FromBase64String(val);
            byte[] keyByte = GetKey(string.Empty);

            // Define a chave privada
            algorithm.Key = keyByte;
            SetAlgorithm();

            // Interface de criptografia / cria objeto de descriptografia
            ICryptoTransform cryptoTransform = algorithm.CreateDecryptor();

            try
            {
                MemoryStream ms = new MemoryStream(cryptoByte, 0, cryptoByte.Length);
                CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Read);

                // Busca resultado do CryptoStream
                StreamReader sr = new StreamReader(cs);
                return sr.ReadToEnd();
            }
            catch { return null; }
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------
    }
}
