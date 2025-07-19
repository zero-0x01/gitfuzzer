"""
Enhanced GitFuzzer Keyword Generation - Real-world programming keywords
"""
import asyncio
import logging
import random
import re
from typing import List, Set

import httpx

logger = logging.getLogger(__name__)


async def generate(subject: str, count: int = 5, hf_token: str = "") -> List[str]:
    """Generate realistic programming keywords for GitHub repository discovery."""
    
    # Try HuggingFace API only if token appears valid
    if hf_token and hf_token.startswith('hf_') and len(hf_token) > 20:
        try:
            # Quick token validation first
            async with httpx.AsyncClient(timeout=5.0) as client:
                auth_response = await client.get(
                    "https://huggingface.co/api/whoami",
                    headers={"Authorization": f"Bearer {hf_token}"}
                )
                
                if auth_response.status_code == 200:
                    # Token is valid, try generation
                    keywords = await _try_huggingface_simple(subject, count, hf_token)
                    if keywords and len(keywords) >= count:
                        logger.info(f"HuggingFace API generated {len(keywords)} keywords")
                        return keywords[:count]
                else:
                    logger.warning(f"HuggingFace token invalid (status: {auth_response.status_code})")
                    
        except Exception as e:
            logger.warning(f"HuggingFace API failed: {e}")
    else:
        if hf_token:
            logger.warning("HuggingFace token appears invalid (wrong format)")
        else:
            logger.info("No HuggingFace token provided, using fallback")
    
    # Enhanced fallback with real-world programming keywords
    logger.info("Using enhanced fallback keyword generation")
    return _generate_realistic_keywords(subject, count)


async def _try_huggingface_simple(subject: str, count: int, token: str) -> List[str]:
    """Simple HuggingFace keyword generation using text completion."""
    
    # Simple completion prompt
    prompt = f"Programming keywords for {subject}:"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api-inference.huggingface.co/models/gpt2",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 50,
                    "temperature": 0.8,
                    "do_sample": True,
                    "return_full_text": False
                }
            }
        )
        
        if response.status_code == 200:
            result = response.json()
            generated_text = ""
            
            if isinstance(result, list) and len(result) > 0:
                generated_text = result[0].get("generated_text", "")
            elif isinstance(result, dict):
                generated_text = result.get("generated_text", "")
            
            if generated_text:
                # Extract keywords from generated text
                words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_-]+\b', generated_text)
                keywords = []
                
                for word in words:
                    if len(word) > 2 and len(word) < 30:
                        keywords.append(word.lower())
                
                # Remove duplicates and return
                unique_keywords = list(dict.fromkeys(keywords))
                return unique_keywords[:count]
        
        raise Exception(f"HuggingFace simple API error: {response.status_code}")


async def _try_huggingface(subject: str, count: int, token: str) -> List[str]:
    """Enhanced HuggingFace keyword generation with better prompts."""
    
    prompt = f"""Generate {count} specific programming keywords for finding GitHub repositories about "{subject}".

Focus on:
- Exact library/framework names that developers use
- Programming language specific terms  
- File extensions and configuration files
- API names and protocol terms
- Database and tool names
- Security and encryption terms

Example for "password": bcrypt, argon2, pbkdf2, scrypt, password-hash, auth-lib, jwt-token

Generate only the keywords, one per line:"""
    
    # Try multiple models in order of preference
    models_to_try = [
        "microsoft/DialoGPT-large",
        "microsoft/DialoGPT-small", 
        "gpt2",
        "distilgpt2"
    ]
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for model in models_to_try:
            try:
                response = await client.post(
                    f"https://api-inference.huggingface.co/models/{model}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "inputs": prompt,
                        "parameters": {
                            "max_new_tokens": 150,
                            "temperature": 0.7,
                            "do_sample": True,
                            "repetition_penalty": 1.1,
                            "return_full_text": False
                        }
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    generated_text = ""
                    
                    # Handle different response formats
                    if isinstance(result, list) and len(result) > 0:
                        if "generated_text" in result[0]:
                            generated_text = result[0]["generated_text"]
                        elif "text" in result[0]:
                            generated_text = result[0]["text"]
                    elif isinstance(result, dict):
                        generated_text = result.get("generated_text", result.get("text", ""))
                    
                    if generated_text:
                        # Extract keywords from generated text
                        lines = generated_text.replace(prompt, "").strip().split('\n')
                        keywords = []
                        
                        for line in lines[:count * 2]:  # Get extra in case some are filtered
                            line = line.strip()
                            if line and not line.startswith('#') and not line.startswith('Generate'):
                                # Clean up the line
                                clean_line = re.sub(r'^[-*\d\.\)]\s*', '', line).strip()
                                if clean_line and len(clean_line.split()) <= 3 and len(clean_line) < 50:
                                    keywords.append(clean_line)
                        
                        if keywords:
                            return keywords[:count]
                
            except Exception as e:
                logger.debug(f"Failed to use model {model}: {e}")
                continue
        
        # If all models fail, raise the last error
        raise Exception(f"All HuggingFace models failed. Last response code: {response.status_code}")


def _generate_realistic_keywords(subject: str, count: int) -> List[str]:
    """Generate realistic programming keywords that would actually appear in code."""
    
    keywords = set()
    subject_lower = subject.lower()
    
    # Convert subject to code-friendly formats
    subject_snake = subject.replace(' ', '_').lower()
    subject_camel = ''.join(word.capitalize() for word in subject.split())
    subject_kebab = subject.replace(' ', '-').lower()
    subject_compact = subject.replace(' ', '').lower()
    
    # Base subject variations (no spaces)
    keywords.add(subject_snake)
    keywords.add(subject_camel)
    keywords.add(subject_kebab)
    keywords.add(subject_compact)
    
    # Programming-specific keyword mappings for code terms (ENHANCED FOR PRIVATE REPOS)
    code_mappings = {
        'internal': [
            'internal_api', 'internal_config', 'internal_service', 'internal_auth', 'internal_admin',
            'internal_database', 'internal_tools', 'company_internal', 'private_internal', 'internal_secrets',
            'internal_portal', 'internal_dashboard', 'internal_system', 'internal_infrastructure'
        ],
        'private': [
            'private_api', 'private_config', 'private_keys', 'private_auth', 'private_admin',
            'company_private', 'private_data', 'private_service', 'private_repo', 'private_access',
            'private_portal', 'private_internal', 'private_secure', 'private_enterprise'
        ],
        'company': [
            'company_api', 'company_config', 'company_auth', 'company_admin', 'company_internal',
            'company_private', 'company_secrets', 'corp_config', 'corporate_api', 'enterprise_config',
            'org_config', 'business_api', 'company_tools', 'company_infrastructure'
        ],
        'enterprise': [
            'enterprise_api', 'enterprise_config', 'enterprise_auth', 'enterprise_admin', 'enterprise_service',
            'corp_enterprise', 'business_enterprise', 'enterprise_portal', 'enterprise_tools', 'enterprise_secrets',
            'enterprise_infrastructure', 'enterprise_security', 'enterprise_internal', 'ent_config'
        ],
        'admin': [
            'admin_panel', 'admin_config', 'admin_api', 'admin_auth', 'admin_dashboard',
            'admin_service', 'admin_portal', 'admin_tools', 'admin_secrets', 'admin_access',
            'admin_interface', 'admin_console', 'admin_system', 'admin_management'
        ],
        'config': [
            'app_config', 'service_config', 'api_config', 'auth_config', 'db_config',
            'server_config', 'prod_config', 'dev_config', 'staging_config', 'config_manager',
            'config_service', 'config_loader', 'environment_config', 'system_config'
        ],
        'secret': [
            'secret_key', 'secret_config', 'secret_manager', 'secret_service', 'secret_store',
            'secret_vault', 'api_secret', 'auth_secret', 'db_secret', 'app_secret',
            'secret_handler', 'secret_provider', 'secret_encryption', 'secret_access'
        ],
        'password': [
            'password_hash', 'password_auth', 'password_service', 'password_manager', 'password_config',
            'password_reset', 'password_validation', 'password_policy', 'password_storage', 'password_encryption',
            'user_password', 'admin_password', 'db_password', 'system_password'
        ],
        'auth': [
            'auth_service', 'auth_config', 'auth_api', 'auth_middleware', 'auth_provider',
            'auth_handler', 'auth_manager', 'oauth_config', 'jwt_auth', 'session_auth',
            'auth_token', 'auth_system', 'auth_portal', 'authentication'
        ],
        'api': [
            'api_key', 'api_secret', 'api_config', 'api_service', 'api_client',
            'api_server', 'api_gateway', 'api_auth', 'api_management', 'api_documentation',
            'rest_api', 'graphql_api', 'api_endpoint', 'api_handler'
        ],
        'crypto': [
            'cryptocurrency', 'cryptography', 'crypto_js', 'libsodium', 'nacl', 'openssl', 
            'bitcoin', 'ethereum', 'web3', 'blockchain', 'ecdsa', 'rsa', 'aes', 'sha256', 
            'secp256k1', 'crypto_hash', 'encrypt_decrypt', 'private_key', 'public_key',
            'cryptojs', 'crypto_utils', 'hash_function', 'digital_signature'
        ],
        'wallet': [
            'wallet_address', 'wallet_balance', 'wallet_manager', 'wallet_service',
            'crypto_wallet', 'digital_wallet', 'wallet_api', 'wallet_sdk', 'wallet_client',
            'wallet_generator', 'wallet_recovery', 'seed_phrase', 'mnemonic', 'keystore'
        ],
        'database': [
            'postgres', 'mysql', 'mongodb', 'redis', 'sqlite', 'orm', 'prisma', 'sequelize',
            'typeorm', 'knex', 'sql', 'nosql', 'migrations', 'db_connection', 'database_url',
            'db_config', 'query_builder', 'connection_pool', 'transaction'
        ],
        'security': [
            'xss_protection', 'csrf_token', 'sql_injection', 'vulnerability', 'security_audit',
            'input_validation', 'data_sanitization', 'encryption_key', 'tls_config', 'ssl_cert',
            'auth_middleware', 'security_header', 'rate_limiting', 'access_control'
        ],
        'web': [
            'react', 'vue', 'angular', 'nextjs', 'nuxtjs', 'svelte', 'webpack', 'vite',
            'tailwind', 'bootstrap', 'sass', 'typescript', 'javascript', 'nodejs',
            'web_component', 'frontend', 'backend', 'fullstack'
        ],
        'smart': [
            'smart_contract', 'contract_address', 'solidity', 'ethereum', 'blockchain',
            'dapp', 'defi', 'nft', 'erc20', 'erc721', 'web3', 'metamask', 'truffle'
        ],
        'contract': [
            'smart_contract', 'contract_deployment', 'contract_interface', 'abi',
            'bytecode', 'gas_limit', 'gas_price', 'contract_call', 'transaction_hash'
        ],
        'machine': [
            'machine_learning', 'ml_model', 'tensorflow', 'pytorch', 'scikit_learn',
            'pandas', 'numpy', 'jupyter', 'deep_learning', 'neural_network', 'nlp',
            'computer_vision', 'data_science', 'ai_model'
        ],
        'learning': [
            'machine_learning', 'deep_learning', 'reinforcement_learning', 'supervised_learning',
            'unsupervised_learning', 'neural_net', 'training_data', 'model_training'
        ],
        'model': [
            'ml_model', 'ai_model', 'model_training', 'model_inference', 'model_deployment',
            'trained_model', 'model_weights', 'model_checkpoint', 'model_evaluation'
        ],
        'authentication': [
            'auth_service', 'user_auth', 'login_system', 'auth_middleware', 'jwt_auth',
            'oauth2', 'saml', 'sso', 'multi_factor', 'two_factor', 'biometric_auth'
        ],
        'aws': [
            'aws_credentials', 'access_key_id', 'secret_access_key', 'aws_config',
            'boto3', 's3_bucket', 'ec2_instance', 'lambda_function', 'iam_role',
            'cloudformation', 'vpc', 'rds', 'dynamodb'
        ],
        'credentials': [
            'api_credentials', 'auth_credentials', 'login_credentials', 'access_credentials',
            'service_account', 'client_secret', 'private_key', 'certificate'
        ],
        'jwt': [
            'jwt_token', 'access_token', 'refresh_token', 'token_validation', 'token_decode',
            'jwt_secret', 'jwt_payload', 'token_expiry', 'bearer_token'
        ],
        'token': [
            'access_token', 'refresh_token', 'auth_token', 'api_token', 'bearer_token',
            'token_validation', 'token_refresh', 'token_storage', 'token_manager'
        ]
    }
    
    # Find matching categories and add code-appropriate terms
    for category, terms in code_mappings.items():
        if category in subject_lower:
            # Add a subset of relevant terms
            selected_terms = random.sample(terms, min(len(terms), 6))
            keywords.update(selected_terms)
    
    # Common programming patterns with proper naming
    base_terms = subject_lower.split()
    if len(base_terms) >= 2:
        # Create realistic variable/function names
        patterns = [
            f"{base_terms[0]}_{base_terms[1]}",
            f"{base_terms[1]}_{base_terms[0]}", 
            f"{''.join(base_terms)}",
            f"{base_terms[0]}{base_terms[1].capitalize()}",
            f"get_{subject_snake}",
            f"set_{subject_snake}",
            f"create_{subject_snake}",
            f"delete_{subject_snake}",
            f"update_{subject_snake}",
            f"validate_{subject_snake}",
            f"{subject_snake}_config",
            f"{subject_snake}_service",
            f"{subject_snake}_manager",
            f"{subject_snake}_handler",
            f"{subject_snake}_utils",
            f"{subject_snake}_helper",
            f"{subject_snake}_client",
            f"{subject_snake}_server",
            f"{subject_snake}_api",
            f"{subject_snake}_lib"
        ]
        keywords.update(patterns)
    
    # File extensions and config files (realistic names)
    file_patterns = [
        f"{subject_compact}.js",
        f"{subject_compact}.py", 
        f"{subject_compact}.go",
        f"{subject_compact}.rs",
        f"{subject_compact}.java",
        f"{subject_snake}.json",
        f"{subject_snake}.yml",
        f"{subject_snake}.yaml",
        f"{subject_snake}.env",
        f"{subject_snake}.config"
    ]
    keywords.update(random.sample(file_patterns, min(len(file_patterns), 4)))
    
    # Common function/method patterns
    function_patterns = [
        f"init_{subject_snake}",
        f"setup_{subject_snake}", 
        f"configure_{subject_snake}",
        f"handle_{subject_snake}",
        f"process_{subject_snake}",
        f"verify_{subject_snake}",
        f"check_{subject_snake}",
        f"validate_{subject_snake}",
        f"{subject_snake}_exists",
        f"{subject_snake}_valid",
        f"is_{subject_snake}",
        f"has_{subject_snake}"
    ]
    keywords.update(random.sample(function_patterns, min(len(function_patterns), 5)))
    
    # Class/interface patterns
    class_patterns = [
        f"{subject_camel}Service",
        f"{subject_camel}Manager", 
        f"{subject_camel}Handler",
        f"{subject_camel}Client",
        f"{subject_camel}Server",
        f"{subject_camel}Config",
        f"{subject_camel}Utils",
        f"{subject_camel}Helper",
        f"{subject_camel}Interface",
        f"{subject_camel}Factory"
    ]
    keywords.update(random.sample(class_patterns, min(len(class_patterns), 4)))
    
    # Convert to list and ensure uniqueness
    keyword_list = list(keywords)
    
    # Filter out any remaining spaces or invalid chars
    clean_keywords = []
    for kw in keyword_list:
        # Only keep keywords that look like valid code identifiers or filenames
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_\-\.]*$', kw) and len(kw) > 2:
            clean_keywords.append(kw)
    
    # If we need more keywords, add generic programming terms
    if len(clean_keywords) < count:
        generic_terms = [
            'config', 'utils', 'helper', 'service', 'manager', 'handler', 
            'client', 'server', 'api', 'sdk', 'lib', 'core', 'base',
            'interface', 'factory', 'builder', 'parser', 'validator',
            'middleware', 'plugin', 'extension', 'module', 'package'
        ]
        
        for term in generic_terms:
            if len(clean_keywords) >= count:
                break
            clean_keywords.append(f"{subject_snake}_{term}")
    
    return clean_keywords[:count]
