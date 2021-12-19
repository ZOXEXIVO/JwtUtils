using BenchmarkDotNet.Running;

namespace JwtUtils.Benchmarks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run<SymmetricBenchmarks>();
            BenchmarkRunner.Run<AsymmetricBenchmarks>();
        }
    }
}