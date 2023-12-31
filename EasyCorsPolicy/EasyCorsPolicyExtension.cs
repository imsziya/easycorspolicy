using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace EasyCorsPolicy
{
    public static class EasyCorsPolicyExtension
    {
        private static string ConfigSectionName => "EasyCors";

        /// <summary>
        /// Adds cross-origin resource sharing services to the specified services
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <exception cref="ArgumentException"></exception>
        public static void AddEasyCorsPolicy(this IServiceCollection services, IConfiguration configuration)
        {
            string policyData = configuration[ConfigSectionName] ?? throw new ArgumentException("Please Add EasyCors policies in your project configuration!");
            Dictionary<string, ConfigurationData> dataDict = JsonSerializer.Deserialize<Dictionary<string, ConfigurationData>>(policyData);
            services.AddCors(options =>
            {
                foreach (KeyValuePair<string, ConfigurationData> data in dataDict)
                {
                    if (data.Value.IsDefault)
                    {
                        options.AddDefaultPolicy(policyBuilder =>
                        {
                            policyBuilder.AddPolicies(data.Value);
                        });
                    }
                    else
                    {
                        options.AddPolicy(name: data.Key, policyBuilder =>
                        {
                            policyBuilder.AddPolicies(data.Value);
                        });
                    }
                }
            });
        }
        public static void UseEasyCors(this IApplicationBuilder applicationBuilder)
        {
            applicationBuilder.UseCors();
        }

        private static void AddPolicies(this CorsPolicyBuilder policyBuilder, ConfigurationData data)
        {
            if (!string.IsNullOrEmpty(data.AllowedOrigins))
            {
                if (data.AllowedOrigins == "*")
                {
                    policyBuilder.AllowAnyOrigin();
                }
                else
                {
                    var allowedOrigins = data.AllowedOrigins.Split(",", StringSplitOptions.RemoveEmptyEntries);
                    policyBuilder.WithOrigins(allowedOrigins);
                }
            }
            if (!string.IsNullOrEmpty(data.AllowedMethods))
            {
                if (data.AllowedMethods == "*")
                {
                    policyBuilder.AllowAnyMethod();
                }
                else
                {
                    var allowedMethods = data.AllowedMethods.Split(",", StringSplitOptions.RemoveEmptyEntries);
                    policyBuilder.WithMethods(allowedMethods);
                }
            }
            if (!string.IsNullOrEmpty(data.AllowedHeaders))
            {
                if (data.AllowedHeaders == "*")
                {
                    policyBuilder.AllowAnyHeader();
                }
                else
                {
                    var allowedHeaders = data.AllowedHeaders.Split(",", StringSplitOptions.RemoveEmptyEntries);
                    policyBuilder.WithHeaders(allowedHeaders);
                }
            }
            if (!string.IsNullOrEmpty(data.AllowedExposedHeaders))
            {
                var allowedExposedHeaders = data.AllowedExposedHeaders.Split(",", StringSplitOptions.RemoveEmptyEntries);
                if (allowedExposedHeaders.Length != 0)
                {
                    policyBuilder.WithExposedHeaders(allowedExposedHeaders);
                }
            }
            if (data.IsAllowedCredentials && data.AllowedOrigins != "*")
            {
                policyBuilder.AllowCredentials();
            }
            else policyBuilder.DisallowCredentials();
        }
    }

    public class ConfigurationData
    {
        public string AllowedOrigins { get; set; }
        public string AllowedHeaders { get; set; }
        public string AllowedExposedHeaders { get; set; }
        public string AllowedMethods { get; set; }
        public bool IsAllowedCredentials { get; set; }
        public bool IsDefault { get; set; }
    }
}