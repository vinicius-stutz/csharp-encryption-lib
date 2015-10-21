using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// TODO: Namespaces, classes and methods are in Portuguese. Feel free to refactor and translate ;).
namespace Criptografia
{
    /// <summary>
    /// <para>@project csharp.encryption (on GitHub Repositories).</para>
    /// <para>@author Vinicius Stutz <http://www.vinicius-stutz.com/>.</para>
    /// <para>@version 1.0 of 19 de Mar 2015.</para>
    /// <para>@license Under the MIT license <http://opensource.org/licenses/MIT>.</para>
    /// <para></para>
    /// <para>Description: DLL/Classe de criptgrafia.</para>
    /// <para></para>
    /// <para>Exemplo de como usar para criptografar:</para>
    /// <para>CryptService crip = new CryptService(CryptProvider.DES);</para>
    /// <para>crip.Key = "MINHA_CHAVE"; // Esta chave você mesmo é quem escolhe</para>
    /// <para>return crip.Criptografar(texto);</para>
    /// <para></para>
    /// <para>Exemplo de como usar para descriptografar:</para>
    /// <para>CryptService crip = new CryptService(CryptProvider.DES);</para>
    /// <para>crip.Key = "MINHA_CHAVE"; // Esta chave tem que ser a mesma do texto criptografado</para>
    /// <para>return crip.Descriptografar(texto);</para>
    /// </summary>
    public class CryptService
    {
        #region Variáveis e Métodos Privados

        private string chave = string.Empty;
        private CryptProvider provider;
        private SymmetricAlgorithm algoritmo;

        /// <summary>Inicialização do vetor do algoritmo simétrico</summary>
        private void SetIV()
        {
            switch (provider)
            {
                case CryptProvider.Rijndael:
                    algoritmo.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9, 0x5, 0x46, 0x9c, 0xea, 0xa8, 0x4b, 0x73, 0xcc };
                    break;
                default:
                    algoritmo.IV = new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 };
                    break;
            }
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------

        #region Properties

        /// <summary>Chave secreta para o algoritmo simétrico de criptografia.</summary>
        public string Key
        {
            get { return chave; }
            set { chave = value; }
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------

        #region Constructors

        /// <summary>Contrutor padrão da classe, é setado um tipo de criptografia padrão (Rijndael).</summary>
        public CryptService()
        {
            algoritmo = new RijndaelManaged();
            algoritmo.Mode = CipherMode.CBC;
            provider = CryptProvider.Rijndael;
        }

        /// <summary>
        /// Construtor com o tipo de criptografia a ser usada Você pode escolher o tipo pelo Enum chamado CryptProvider.
        /// </summary>
        /// <param name="cryptProvider">Tipo de criptografia.</param>
        public CryptService(CryptProvider cryptProvider)
        {
            // Seleciona algoritmo simétrico
            switch (cryptProvider)
            {
                case CryptProvider.Rijndael:
                    algoritmo = new RijndaelManaged();
                    provider = CryptProvider.Rijndael;
                    break;

                case CryptProvider.RC2:
                    algoritmo = new RC2CryptoServiceProvider();
                    provider = CryptProvider.RC2;
                    break;

                case CryptProvider.DES:
                    algoritmo = new DESCryptoServiceProvider();
                    provider = CryptProvider.DES;
                    break;

                case CryptProvider.TripleDES:
                    algoritmo = new TripleDESCryptoServiceProvider();
                    provider = CryptProvider.TripleDES;
                    break;
            }
            algoritmo.Mode = CipherMode.CBC;
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------

        #region Public methods

        /// <summary>Gera a chave de criptografia válida dentro do array.</summary>
        /// <returns>Chave com array de bytes.</returns>
        public virtual byte[] GetChave()
        {
            string salt = string.Empty;

            // Ajusta o tamanho da chave se necessário e retorna uma chave válida
            if (algoritmo.LegalKeySizes.Length > 0)
            {
                // Tamanho das chaves em bits
                int keySize = chave.Length * 8;
                int minSize = algoritmo.LegalKeySizes[0].MinSize;
                int maxSize = algoritmo.LegalKeySizes[0].MaxSize;
                int skipSize = algoritmo.LegalKeySizes[0].SkipSize;

                // Busca o valor máximo da chave
                if (keySize > maxSize) { chave = chave.Substring(0, maxSize / 8); }
                else if (keySize < maxSize)
                {
                    // Seta um tamanho válido
                    int validSize = (keySize <= minSize) ? minSize : (keySize - keySize % skipSize) + skipSize;
                    validSize = validSize / 8;
                    // Preenche a chave com arterisco para corrigir o tamanho
                    if (keySize < validSize) { chave = chave.PadRight(validSize, Convert.ToChar("*")); } // validSize / 8, "*".ToString()
                }
            }
            PasswordDeriveBytes key = new PasswordDeriveBytes(chave, ASCIIEncoding.ASCII.GetBytes(salt));
            return key.GetBytes(chave.Length);
        }


        /// <summary>Encripta o dado solicitado.</summary>
        /// <param name="texto">Texto a ser criptografado.</param>
        /// <returns>Texto criptografado.</returns>
        public virtual string Criptografar(string texto)
        {
            byte[] plainByte = Encoding.UTF8.GetBytes(texto);
            byte[] keyByte = GetChave();

            // Seta a chave privada
            algoritmo.Key = keyByte;

            SetIV();

            // Interface de criptografia / Cria objeto de criptografia
            ICryptoTransform cryptoTransform = algoritmo.CreateEncryptor();

            MemoryStream _memoryStream = new MemoryStream();

            CryptoStream _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Write);

            // Grava os dados criptografados no MemoryStream
            _cryptoStream.Write(plainByte, 0, plainByte.Length);
            _cryptoStream.FlushFinalBlock();

            // Busca o tamanho dos bytes encriptados
            byte[] cryptoByte = _memoryStream.ToArray();

            // Converte para a base 64 string para uso posterior em um xml
            return Convert.ToBase64String(cryptoByte, 0, cryptoByte.GetLength(0));
        }


        /// <summary>Desencripta o dado solicitado.</summary>
        /// <param name="textoCriptografado">Texto a ser descriptografado.</param>
        /// <returns>Texto descriptografado.</returns>
        public virtual string Descriptografar(string textoCriptografado)
        {

            // Em caso de "Invalid length for a Base-64 char array"
            textoCriptografado = textoCriptografado.Replace(" ", "+");
            int mod4 = textoCriptografado.Length % 4;
            if (mod4 > 0) textoCriptografado += new string('=', 4 - mod4);

            // Converte a base 64 string em num array de bytes
            byte[] cryptoByte = Convert.FromBase64String(textoCriptografado);
            byte[] keyByte = GetChave();

            // Seta a chave privada
            algoritmo.Key = keyByte;
            SetIV();

            // Interface de criptografia / Cria objeto de descriptografia
            ICryptoTransform cryptoTransform = algoritmo.CreateDecryptor();

            try
            {
                MemoryStream _memoryStream = new MemoryStream(cryptoByte, 0, cryptoByte.Length);
                CryptoStream _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Read);

                // Busca resultado do CryptoStream
                StreamReader _streamReader = new StreamReader(_cryptoStream);
                return _streamReader.ReadToEnd();
            }
            catch { return null; }
        }

        #endregion

        // ----------------------------------------------------------------------------------------------------
    }
}
