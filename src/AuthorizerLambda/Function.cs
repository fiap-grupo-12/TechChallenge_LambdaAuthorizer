using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using System.Collections.Generic;
using System.Threading.Tasks;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace AuthorizerLambda
{
    public class Function
    {
        private readonly string _userPoolId;
        private readonly AmazonCognitoIdentityProviderClient _client;

        public Function()
        {
            // Obter o User Pool ID da variável de ambiente passada pelo Terraform
            _userPoolId = Environment.GetEnvironmentVariable("USER_POOL_ID");
            _client = new AmazonCognitoIdentityProviderClient();
        }

        public async Task<APIGatewayCustomAuthorizerResponse> FunctionHandler(APIGatewayCustomAuthorizerRequest request)
        {

            // Verifica se o dicionário Headers existe e se contém a chave "cpf"
            if (request.Headers == null || !request.Headers.ContainsKey("cpf") || string.IsNullOrEmpty(request.Headers["cpf"]))
            {
                // Libera o acesso se o header CPF não estiver presente ou estiver vazio
                return GenerateAllowResponse(request.MethodArn);
            }

            // Captura o valor do CPF
            string cpf = request.Headers["cpf"];

            // Validar o CPF no Cognito
            bool isValid = await ValidateCPF(cpf);

            // Se o CPF for inválido ou não encontrado, negar o acesso
            if (!isValid)
            {
                return GenerateDenyResponse(request.MethodArn, "CPF inválido ou não encontrado");
            }

            // CPF válido, permitir o acesso
            return GenerateAllowResponse(request.MethodArn);
        }

        // Método para validar o CPF no Cognito
        private async Task<bool> ValidateCPF(string cpf)
        {
            if (cpf == "anonimo")
            {
                return true;
            }
            var request = new ListUsersRequest
            {
                UserPoolId = _userPoolId,
                Filter = $"username = \"{cpf}\""  // Assumindo que o CPF é o username no Cognito
            };

            var response = await _client.ListUsersAsync(request);
            return response.Users.Count > 0; // Retorna true se o CPF estiver cadastrado
        }


        private APIGatewayCustomAuthorizerResponse GenerateAllowResponse(string methodArn)
        {
            return new APIGatewayCustomAuthorizerResponse
            {
                principalId = "user",
                policyDocument = new APIGatewayCustomAuthorizerPolicy
                {
                    Version = "2012-10-17",
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.StatementLocal>
                {
                    new APIGatewayCustomAuthorizerPolicy.StatementLocal
                    {
                        Action = "execute-api:Invoke",
                        Effect = "Allow",
                        Resource = new List<string> { methodArn }
                    }
                }
                }
            };
        }

        private APIGatewayCustomAuthorizerResponse GenerateDenyResponse(string methodArn, string message)
        {
            return new APIGatewayCustomAuthorizerResponse
            {
                principalId = "user",
                policyDocument = new APIGatewayCustomAuthorizerPolicy
                {
                    Version = "2012-10-17",
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.StatementLocal>
                {
                    new APIGatewayCustomAuthorizerPolicy.StatementLocal
                    {
                        Action = "execute-api:Invoke",
                        Effect = "Deny",
                        Resource = new List<string> { methodArn }
                    }
                }
                }
            };
        }
    }

    // Classes de suporte para o APIGatewayCustomAuthorizerResponse
    public class APIGatewayCustomAuthorizerResponse
    {
        public string? principalId { get; set; }
        public APIGatewayCustomAuthorizerPolicy? policyDocument { get; set; }
    }

    public class APIGatewayCustomAuthorizerPolicy
    {
        public string? Version { get; set; }
        public List<StatementLocal>? Statement { get; set; }

        public class StatementLocal
        {
            public string? Effect { get; set; }
            public string? Action { get; set; }
            public List<string>? Resource { get; set; }
        }
    }
}
