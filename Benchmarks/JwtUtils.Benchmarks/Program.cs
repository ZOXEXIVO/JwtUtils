using BenchmarkDotNet.Running;
using Microsoft.IdentityModel.Logging;

namespace JwtUtils.Benchmarks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            IdentityModelEventSource.ShowPII = true;

            //var t = SymmetricBenchmarks.JwtSecurityTokenHandler_HS256_Validate();
            
            //BenchmarkRunner.Run<SymmetricBenchmarks>();
            BenchmarkRunner.Run<AsymmetricBenchmarks>();
        }
    }
}