using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using System;
using System.IO;
using System.Threading.Tasks;
namespace PacktPub.AzureStorage.Demos
{

    class Program
    {
        private static string ConnectionString => "";

        private const string BlobName = "Books";

        // References for the cloud objects.
        private static CloudStorageAccount account;
        private static CloudBlobClient blobClient;
        private static CloudBlobContainer container;

        private static string filePath = @"C:\Temp\LOG01.LOG";
        private static string newFile = @"C:\Temp\NewFile_LOG01.LOG";

        private static string containerName = "documents-container";
        private static string StorageAccountName = "packtpubcoursestorage";

        static void Main(string[] args)
        {
            // 1. Establish a connection.
            establishConnection();

            if (account != null)
            {
                // Get the reference to the blob.
                blobClient = account.CreateCloudBlobClient();
                Console.WriteLine("[Connection] Connected successfully, uploading file now...");

                runTasks();
            }

            Console.Read();
        }

        private async static void runTasks()
        {
            // 2. Create a container.
            var isCreated = await createContainer(containerName);

           //  3. Upload the file.
            await uploadBlob(filePath);

            //// 4. Download the file.
            //await downloadBlob(newFile);

            //// 5. Print the SAS token.
            //await getSasToken(filePath);

            //// 6. Print the content.
            //printContent(newFile);

        

           var fullUrl = await GetBlobSasUriAsync(container, GetBlobName(filePath));
            Console.WriteLine(fullUrl);


            // 7. Delete the blob.
            // await deleteBlobFile(filePath);
        }

        private static void establishConnection()
        {
            if (!CloudStorageAccount.TryParse(ConnectionString, out account))
            {
                Console.WriteLine("[Connection] Connection string is invalid.");
            }
        }

        private   static Task<bool> createContainer(string containerName)
        {
            container = blobClient.GetContainerReference(containerName);
            // Validation.
            return container.CreateIfNotExistsAsync();
        }

        private async static Task uploadBlob(string filePath)
        {
            var blobReference = container.GetBlockBlobReference(GetBlobName(filePath));
            using (var file = File.OpenRead(filePath))
            {
                await blobReference.UploadFromStreamAsync(file);
                Console.WriteLine("[Upload] File uploaded successfully.");
            }
        }

        private static string GetBlobName(string filePath)
        {
            return Path.Combine(BlobName, Path.GetFileName(filePath));
        }

        private async static Task downloadBlob(string fileName)
        {
            var blobReference = container.GetBlockBlobReference(GetBlobName(filePath));

            await blobReference.DownloadToFileAsync(fileName, FileMode.OpenOrCreate);
            Console.WriteLine("[Download] File downloaded successfully.");
        }

        private async static Task getSasToken(string fileName)
        {
            var blobReference = container.GetBlockBlobReference(GetBlobName(fileName));
            if (await blobReference.ExistsAsync())
            {
                var token = blobReference.GetSharedAccessSignature(new SharedAccessBlobPolicy
                {
                    SharedAccessExpiryTime = DateTime.Now.AddDays(1)
                });

                Console.WriteLine($"The SAS token for the required policy is: {token}.");
            }
        }


        private static Task<string> GetBlobSasUriAsync(CloudBlobContainer container, string blobName, string policyName = null)
        {
            return Task.Run(() => GetBlobSasUri(container, blobName, policyName)); 
        }

        private static string GetBlobSasUri(CloudBlobContainer container, string blobName, string policyName = null)
        {
            string sasBlobToken;

            // Get a reference to a blob within the container.
            // Note that the blob may not exist yet, but a SAS can still be created for it.
            CloudBlockBlob blob = container.GetBlockBlobReference(blobName);

            if (policyName == null)
            {
                // Create a new access policy and define its constraints.
                // Note that the SharedAccessBlobPolicy class is used both to define the parameters of an ad hoc SAS, and
                // to construct a shared access policy that is saved to the container's shared access policies.
                SharedAccessBlobPolicy adHocSAS = new SharedAccessBlobPolicy()
                {
                    // When the start time for the SAS is omitted, the start time is assumed to be the time when the storage service receives the request.
                    // Omitting the start time for a SAS that is effective immediately helps to avoid clock skew.
                    SharedAccessExpiryTime = DateTime.UtcNow.AddHours(24),
                    Permissions = SharedAccessBlobPermissions.Read | SharedAccessBlobPermissions.Write | SharedAccessBlobPermissions.Create
                };

                // Generate the shared access signature on the blob, setting the constraints directly on the signature.
                sasBlobToken = blob.GetSharedAccessSignature(adHocSAS);

                Console.WriteLine("SAS for blob (ad hoc): {0}", sasBlobToken);
                Console.WriteLine();
            }
            else
            {
                // Generate the shared access signature on the blob. In this case, all of the constraints for the
                // shared access signature are specified on the container's stored access policy.
                sasBlobToken = blob.GetSharedAccessSignature(null, policyName);

                Console.WriteLine("SAS for blob (stored access policy): {0}", sasBlobToken);
                Console.WriteLine();
            }

            // Return the URI string for the container, including the SAS token.
            return blob.Uri + sasBlobToken;
        }



        //async static Task<Uri> GetUserDelegationSasBlob( string blobName)
        //{
        //    // Construct the blob endpoint from the account name.
        //    string blobEndpoint = string.Format("https://{0}.blob.core.windows.net", StorageAccountName);

        //    // Create a new Blob service client with Azure AD credentials.  
        //    BlobServiceClient blobClient = new BlobServiceClient(new Uri(blobEndpoint),
        //                                                            new DefaultAzureCredential());

        //    // Get a user delegation key for the Blob service that's valid for seven days.
        //    // You can use the key to generate any number of shared access signatures over the lifetime of the key.
        //    UserDelegationKey key = await blobClient.GetUserDelegationKeyAsync(DateTimeOffset.UtcNow,
        //                                                                        DateTimeOffset.UtcNow.AddDays(7));

        //    // Read the key's properties.
        //    Console.WriteLine("User delegation key properties:");
        //    Console.WriteLine("Key signed start: {0}", key.SignedStartsOn);
        //    Console.WriteLine("Key signed expiry: {0}", key.SignedExpiresOn);
        //    Console.WriteLine("Key signed object ID: {0}", key.SignedObjectId);
        //    Console.WriteLine("Key signed tenant ID: {0}", key.SignedTenantId);
        //    Console.WriteLine("Key signed service: {0}", key.SignedService);
        //    Console.WriteLine("Key signed version: {0}", key.SignedVersion);
        //    Console.WriteLine();

        //    // Create a SAS token that's valid for one hour.
        //    BlobSasBuilder sasBuilder = new BlobSasBuilder()
        //    {
        //        BlobContainerName = containerName,
        //        BlobName = blobName,
        //        Resource = "b",
        //        StartsOn = DateTimeOffset.UtcNow,
        //        ExpiresOn = DateTimeOffset.UtcNow.AddHours(1)
        //    };

        //    // Specify read permissions for the SAS.
        //    sasBuilder.SetPermissions(BlobSasPermissions.Read);

        //    // Use the key to get the SAS token.
        //    string sasToken = sasBuilder.ToSasQueryParameters(key, StorageAccountName).ToString();

        //    // Construct the full URI, including the SAS token.
        //    UriBuilder fullUri = new UriBuilder()
        //    {
        //        Scheme = "https",
        //        Host = string.Format("{0}.blob.core.windows.net", StorageAccountName),
        //        Path = string.Format("{0}/{1}", containerName, blobName),
        //        Query = sasToken
        //    };

        //    Console.WriteLine("User delegation SAS URI: {0}", fullUri);
        //    Console.WriteLine();
        //    return fullUri.Uri;
        //}




        private async static Task deleteBlobFile(string fileName)
        {
            var blobReference = container.GetBlockBlobReference(GetBlobName(fileName));
            if (await blobReference.DeleteIfExistsAsync())
            {
                Console.WriteLine("[Delete] Blob was deleted.");
            }
            else
            {
                Console.WriteLine("[Delete] Blob cannot be deleted.");
            }
        }

        private static void printContent(string fileName)
        {
            string content = File.ReadAllText(fileName);
            Console.WriteLine();
            Console.WriteLine("Content of the file downloaded is:");
            Console.WriteLine(content);
        }
    }
}


