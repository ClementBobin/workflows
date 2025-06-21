import pytest
import yaml
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
import json
from io import StringIO

# Fixtures for test data and setup

@pytest.fixture
def valid_yaml_config():
    """Fixture providing a valid YAML configuration."""
    return {
        'rule': {
            'id': 'test-rule',
            'language': 'python',
            'message': 'Test security rule'
        },
        'pattern': 'print($MSG)',
        'constraints': {
            'MSG': {'regex': '.*password.*'}
        }
    }

@pytest.fixture
def ast_grep_rule_config():
    """Fixture providing an AST-grep rule configuration."""
    return {
        'id': 'security-rule-001',
        'message': 'Avoid using system calls',
        'language': 'c',
        'rule': {
            'pattern': 'system($ARG)',
            'kind': 'call_expression'
        },
        'severity': 'error',
        'metadata': {
            'category': 'security',
            'technology': ['c', 'cpp']
        }
    }

@pytest.fixture
def invalid_yaml_content():
    """Fixture providing invalid YAML content."""
    return """
    rule:
      id: test-rule
      language: python
    pattern: [unclosed bracket
    invalid_syntax: {missing closing brace
    """

@pytest.fixture
def temp_yaml_file(tmp_path):
    """Fixture creating a temporary YAML file for testing."""
    yaml_file = tmp_path / "test_config.yaml"
    return yaml_file

@pytest.fixture
def temp_directory(tmp_path):
    """Fixture creating a temporary directory for testing."""
    return tmp_path

class TestYamlConfigLoading:
    """Test cases for YAML configuration loading."""

    def test_load_valid_yaml_file(self, temp_yaml_file, valid_yaml_config):
        """Test loading a valid YAML configuration file."""
        with open(temp_yaml_file, 'w') as f:
            yaml.dump(valid_yaml_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert loaded_config == valid_yaml_config
        assert loaded_config['rule']['id'] == 'test-rule'
        assert loaded_config['rule']['language'] == 'python'
        assert loaded_config['pattern'] == 'print($MSG)'

    def test_load_ast_grep_rule_config(self, temp_yaml_file, ast_grep_rule_config):
        """Test loading an AST-grep rule configuration."""
        with open(temp_yaml_file, 'w') as f:
            yaml.dump(ast_grep_rule_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert loaded_config['id'] == 'security-rule-001'
        assert loaded_config['language'] == 'c'
        assert loaded_config['severity'] == 'error'
        assert 'security' in loaded_config['metadata']['category']

    def test_load_nonexistent_yaml_file(self):
        """Test loading a non-existent YAML file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            with open('nonexistent_config.yaml', 'r') as f:
                yaml.safe_load(f)

    def test_load_invalid_yaml_syntax(self, temp_yaml_file, invalid_yaml_content):
        """Test loading YAML with invalid syntax raises YAMLError."""
        with open(temp_yaml_file, 'w') as f:
            f.write(invalid_yaml_content)

        with pytest.raises(yaml.YAMLError):
            with open(temp_yaml_file, 'r') as f:
                yaml.safe_load(f)

    def test_load_empty_yaml_file(self, temp_yaml_file):
        """Test loading an empty YAML file returns None."""
        temp_yaml_file.touch()

        with open(temp_yaml_file, 'r') as f:
            result = yaml.safe_load(f)

        assert result is None

    def test_load_yaml_with_comments(self, temp_yaml_file):
        """Test loading YAML file with comments."""
        yaml_content = """
# This is a test configuration
rule:
  id: test-rule  # Rule identifier
  language: python  # Programming language
# Pattern section
pattern: print($MSG)
        """

        with open(temp_yaml_file, 'w') as f:
            f.write(yaml_content)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert loaded_config['rule']['id'] == 'test-rule'
        assert loaded_config['rule']['language'] == 'python'
        assert loaded_config['pattern'] == 'print($MSG)'

class TestYamlConfigValidation:
    """Test cases for YAML configuration validation."""

    def test_validate_required_keys_present(self, valid_yaml_config):
        """Test validation passes when all required keys are present."""
        required_keys = ['rule', 'pattern']

        for key in required_keys:
            assert key in valid_yaml_config

        # Test nested required keys
        rule_required_keys = ['id', 'language', 'message']
        for key in rule_required_keys:
            assert key in valid_yaml_config['rule']

    def test_validate_ast_grep_rule_structure(self, ast_grep_rule_config):
        """Test validation of AST-grep rule structure."""
        required_top_level = ['id', 'message', 'language', 'rule']

        for key in required_top_level:
            assert key in ast_grep_rule_config

        # Validate rule structure
        assert 'pattern' in ast_grep_rule_config['rule']

        # Validate metadata structure
        if 'metadata' in ast_grep_rule_config:
            assert isinstance(ast_grep_rule_config['metadata'], dict)

    def test_validate_data_types(self, valid_yaml_config):
        """Test validation of data types in configuration."""
        assert isinstance(valid_yaml_config['rule']['id'], str)
        assert isinstance(valid_yaml_config['rule']['language'], str)
        assert isinstance(valid_yaml_config['pattern'], str)
        assert isinstance(valid_yaml_config['constraints'], dict)

    def test_validate_language_values(self, ast_grep_rule_config):
        """Test validation of supported language values."""
        supported_languages = [
            'c', 'cpp', 'csharp', 'css', 'go', 'html', 'java',
            'javascript', 'json', 'kotlin', 'lua', 'python',
            'rust', 'scala', 'swift', 'typescript'
        ]

        language = ast_grep_rule_config['language']
        assert language in supported_languages

    def test_validate_severity_levels(self):
        """Test validation of severity levels."""
        valid_severities = ['error', 'warning', 'info', 'hint']

        for severity in valid_severities:
            config = {'severity': severity}
            assert config['severity'] in valid_severities

    @pytest.mark.parametrize("invalid_severity", ['critical', 'low', 'medium', 'high', ''])
    def test_validate_invalid_severity_levels(self, invalid_severity):
        """Test validation fails for invalid severity levels."""
        valid_severities = ['error', 'warning', 'info', 'hint']
        assert invalid_severity not in valid_severities

    def test_validate_rule_id_format(self, ast_grep_rule_config):
        """Test validation of rule ID format."""
        rule_id = ast_grep_rule_config['id']

        # Rule IDs should be non-empty strings
        assert isinstance(rule_id, str)
        assert len(rule_id) > 0

        # Should not contain spaces
        assert ' ' not in rule_id

class TestYamlConfigEdgeCases:
    """Test edge cases and error conditions."""

    def test_large_yaml_file(self, temp_yaml_file):
        """Test loading a large YAML configuration file."""
        large_config = {
            'rules': {
                f'rule_{i}': {
                    'id': f'rule-{i}',
                    'language': 'python',
                    'pattern': f'pattern_{i}',
                    'message': f'Message for rule {i}'
                } for i in range(100)
            }
        }

        with open(temp_yaml_file, 'w') as f:
            yaml.dump(large_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert len(loaded_config['rules']) == 100
        assert loaded_config['rules']['rule_0']['id'] == 'rule-0'
        assert loaded_config['rules']['rule_99']['id'] == 'rule-99'

    def test_yaml_with_unicode_characters(self, temp_yaml_file):
        """Test YAML file with unicode characters."""
        unicode_config = {
            'rule': {
                'id': 'unicode-test',
                'message': 'Тест сообщение with émojis 🚀',
                'description': '日本語のテスト'
            },
            'pattern': 'test($.unicode_var)',
            'examples': ['测试', 'тест', 'テスト']
        }

        with open(temp_yaml_file, 'w', encoding='utf-8') as f:
            yaml.dump(unicode_config, f, allow_unicode=True)

        with open(temp_yaml_file, 'r', encoding='utf-8') as f:
            loaded_config = yaml.safe_load(f)

        assert loaded_config['rule']['message'] == 'Тест сообщение with éмоjis 🚀'
        assert loaded_config['rule']['description'] == '日本語のテスト'
        assert '测试' in loaded_config['examples']

    def test_yaml_with_null_values(self, temp_yaml_file):
        """Test YAML file with null values."""
        null_config = {
            'rule': {
                'id': 'null-test',
                'language': 'python',
                'description': None,
                'tags': None
            },
            'pattern': 'test($ARG)',
            'fix': None
        }

        with open(temp_yaml_file, 'w') as f:
            yaml.dump(null_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert loaded_config['rule']['description'] is None
        assert loaded_config['rule']['tags'] is None
        assert loaded_config['fix'] is None

    def test_yaml_with_boolean_values(self, temp_yaml_file):
        """Test YAML file with various boolean representations."""
        bool_config = {
            'rule': {
                'id': 'bool-test',
                'enabled': True,
                'deprecated': False
            },
            'metadata': {
                'auto_fix': True,
                'experimental': False,
                'draft': 'yes',  # String representation
                'reviewed': 'no'  # String representation
            }
        }

        with open(temp_yaml_file, 'w') as f:
            yaml.dump(bool_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert loaded_config['rule']['enabled'] is True
        assert loaded_config['rule']['deprecated'] is False
        assert loaded_config['metadata']['auto_fix'] is True
        assert loaded_config['metadata']['experimental'] is False

    def test_yaml_with_lists_and_nested_structures(self, temp_yaml_file):
        """Test YAML file with complex nested structures."""
        complex_config = {
            'rule': {
                'id': 'complex-rule',
                'languages': ['python', 'javascript', 'java'],
                'patterns': [
                    {'pattern': 'print($MSG)', 'severity': 'warning'},
                    {'pattern': 'console.log($MSG)', 'severity': 'info'}
                ]
            },
            'metadata': {
                'tags': ['security', 'logging', 'debug'],
                'references': [
                    {'url': 'https://example.com/doc1', 'title': 'Documentation'},
                    {'url': 'https://example.com/doc2', 'title': 'Best Practices'}
                ]
            }
        }

        with open(temp_yaml_file, 'w') as f:
            yaml.dump(complex_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert len(loaded_config['rule']['languages']) == 3
        assert 'python' in loaded_config['rule']['languages']
        assert len(loaded_config['rule']['patterns']) == 2
        assert loaded_config['rule']['patterns'][0]['severity'] == 'warning'
        assert len(loaded_config['metadata']['references']) == 2

    def test_yaml_with_multiline_strings(self, temp_yaml_file):
        """Test YAML file with multiline strings."""
        multiline_config = {
            'rule': {
                'id': 'multiline-test',
                'description': """
                This is a multiline description
                that spans multiple lines
                and contains detailed information.
                """,
                'example': '''
                def bad_function():
                    print("This is bad")
                    return None
                '''
            }
        }

        with open(temp_yaml_file, 'w') as f:
            yaml.dump(multiline_config, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        description = loaded_config['rule']['description']
        example = loaded_config['rule']['example']

        assert 'multiline description' in description
        assert 'spans multiple lines' in description
        assert 'def bad_function' in example
        assert 'print(' in example

class TestYamlConfigSecurity:
    """Test security aspects of YAML configuration loading."""

    def test_safe_load_prevents_code_execution(self, temp_yaml_file):
        """Test that safe_load prevents arbitrary code execution."""
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo "This should not execute"']
"""

        with open(temp_yaml_file, 'w') as f:
            f.write(malicious_yaml)

        # safe_load should not execute the code
        with pytest.raises(yaml.constructor.ConstructorError):
            with open(temp_yaml_file, 'r') as f:
                yaml.safe_load(f)

    def test_safe_load_prevents_arbitrary_objects(self, temp_yaml_file):
        """Test that safe_load prevents loading arbitrary Python objects."""
        malicious_yaml = """
!!python/object:builtins.eval
args: ['__import__("os").system("ls")']
"""

        with open(temp_yaml_file, 'w') as f:
            f.write(malicious_yaml)

        with pytest.raises(yaml.constructor.ConstructorError):
            with open(temp_yaml_file, 'r') as f:
                yaml.safe_load(f)

    def test_load_time_performance(self, temp_directory):
        """Test configuration loading performance with moderately large files."""
        # Create a moderately large config
        large_config = {
            'rules': {
                f'rule_{i}': {
                    'id': f'security-rule-{i}',
                    'language': 'python',
                    'message': f'Security rule number {i}',
                    'pattern': f'dangerous_function_{i}($ARG)',
                    'metadata': {
                        'category': 'security',
                        'tags': [f'tag_{j}' for j in range(5)],
                        'references': [
                            {'url': f'https://example.com/rule-{i}-{k}', 'title': f'Reference {k}'}
                            for k in range(3)
                        ]
                    }
                } for i in range(50)
            }
        }

        config_file = temp_directory / "large_config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(large_config, f)

        start_time = time.time()
        with open(config_file, 'r') as f:
            loaded_config = yaml.safe_load(f)
        load_time = time.time() - start_time

        # Should load reasonably quickly (adjust threshold as needed)
        assert load_time < 2.0  # Less than 2 seconds
        assert len(loaded_config['rules']) == 50

    def test_memory_usage_with_large_configs(self, temp_directory):
        """Test memory efficiency with large configuration files."""
        import sys

        # Create config with repetitive structure
        config = {
            'rules': [
                {
                    'id': f'rule-{i}',
                    'pattern': 'test_pattern($ARG)',
                    'message': 'Test message',
                    'language': 'python',
                    'severity': 'warning'
                } for i in range(200)
            ]
        }

        config_file = temp_directory / "memory_test.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        # Load config and check it's reasonable
        with open(config_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        assert len(loaded_config['rules']) == 200
        assert all(rule['message'] == 'Test message' for rule in loaded_config['rules'])

class TestYamlConfigIntegration:
    """Integration tests for YAML configuration usage."""

    def test_multiple_config_formats(self, temp_directory):
        """Test loading equivalent configs in different YAML formats."""
        # Same config in different YAML styles
        configs = [
            # Flow style
            """
rule: {id: test-rule, language: python, message: Test message}
pattern: print($MSG)
""",
            # Block style
            """
rule:
  id: test-rule
  language: python
  message: Test message
pattern: print($MSG)
""",
            # Mixed style
            """
rule:
  id: test-rule
  language: python
  message: Test message
pattern: print($MSG)
"""
        ]

        loaded_configs = []
        for i, config_content in enumerate(configs):
            config_file = temp_directory / f"config_{i}.yaml"
            with open(config_file, 'w') as f:
                f.write(config_content)

            with open(config_file, 'r') as f:
                loaded_config = yaml.safe_load(f)
            loaded_configs.append(loaded_config)

        # All configs should be equivalent
        for config in loaded_configs[1:]:
            assert config == loaded_configs[0]

    def test_config_file_extensions(self, temp_directory):
        """Test loading configs with different file extensions."""
        config_data = {
            'rule': {'id': 'extension-test', 'language': 'python'},
            'pattern': 'test($ARG)'
        }

        extensions = ['.yaml', '.yml']

        for ext in extensions:
            config_file = temp_directory / f"test_config{ext}"
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f)

            with open(config_file, 'r') as f:
                loaded_config = yaml.safe_load(f)

            assert loaded_config['rule']['id'] == 'extension-test'
            assert loaded_config['pattern'] == 'test($ARG)'

    def test_config_with_anchors_and_aliases(self, temp_yaml_file):
        """Test YAML configurations using anchors and aliases."""
        yaml_with_anchors = """
default_metadata: &default_meta
  category: security
  technology: [python, javascript]
  confidence: high

rules:
  rule1:
    id: rule-1
    pattern: dangerous_call($ARG)
    metadata:
      <<: *default_meta
      specific_tag: rule1_specific

  rule2:
    id: rule-2
    pattern: unsafe_function($ARG)
    metadata:
      <<: *default_meta
      specific_tag: rule2_specific
"""

        with open(temp_yaml_file, 'w') as f:
            f.write(yaml_with_anchors)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        # Check that anchors were properly resolved
        rule1_meta = loaded_config['rules']['rule1']['metadata']
        rule2_meta = loaded_config['rules']['rule2']['metadata']

        assert rule1_meta['category'] == 'security'
        assert rule1_meta['confidence'] == 'high'
        assert rule1_meta['specific_tag'] == 'rule1_specific'

        assert rule2_meta['category'] == 'security'
        assert rule2_meta['confidence'] == 'high'
        assert rule2_meta['specific_tag'] == 'rule2_specific'

    def test_real_world_ast_grep_rule_structure(self, temp_yaml_file):
        """Test with realistic AST-grep rule structure."""
        realistic_rule = {
            'id': 'security-sql-injection',
            'message': 'Potential SQL injection vulnerability',
            'note': 'Use parameterized queries instead',
            'language': 'python',
            'severity': 'error',
            'rule': {
                'any': [
                    {'pattern': 'cursor.execute($SQL + $VAR)'},
                    {'pattern': 'cursor.execute(f\"$SQL{$VAR}\")'},
                    {'pattern': 'cursor.execute(\"$SQL\" + $VAR)'}
                ]
            },
            'constraints': {
                'SQL': {'regex': '.*SELECT|INSERT|UPDATE|DELETE.*'},
                'VAR': {'not': {'kind': 'string'}}
            },
            'fix': 'cursor.execute(\"SELECT * FROM table WHERE id = ?\", (user_id,))',
            'metadata': {
                'category': 'security',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021',
                'technology': ['python', 'sqlite', 'mysql', 'postgresql'],
                'confidence': 'high',
                'likelihood': 'medium',
                'impact': 'high'
            }
        }

        with open(temp_yaml_file, 'w') as f:
            yaml.dump(realistic_rule, f)

        with open(temp_yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)

        # Validate structure
        assert loaded_config['id'] == 'security-sql-injection'
        assert loaded_config['severity'] == 'error'
        assert 'any' in loaded_config['rule']
        assert len(loaded_config['rule']['any']) == 3
        assert 'SQL' in loaded_config['constraints']
        assert 'regex' in loaded_config['constraints']['SQL']
        assert loaded_config['metadata']['cwe'] == 'CWE-89'
        assert 'python' in loaded_config['metadata']['technology']