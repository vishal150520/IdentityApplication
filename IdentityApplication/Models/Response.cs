using Newtonsoft.Json;

namespace IdentityServer.Models
{
    public class Response
    {
        public bool Success { get; set; } = false;
        public int StatusCode { get; private set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string? Message { get; private set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public object Result { get; private set; }

        public Response(int statusCode, string message)
            : this(statusCode)
        {
            this.Message = message;
        }

        public Response(object result, string? message = null) :
          this(200)
        {
            Result = result;
            this.Message = message;
            this.Success = true;
        }

        public Response(int statusCode)
        {
            this.StatusCode = statusCode;
        }
    }
}
