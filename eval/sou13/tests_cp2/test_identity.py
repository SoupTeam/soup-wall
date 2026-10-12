import unittest

from sou13cp2.identity import (effect_profile_from_trace, name_tokens, normalized_description, schema_fingerprint,
                               template_signature)


class NameNormalisation(unittest.TestCase):
    def test_aliases_collapse(self):
        for alias in ('fetch_url', 'FetchUrl', 'url-fetch', 'fetch_url_v2', 'fetch_url_adapter', 'fetchURL2'):
            with self.subTest(alias=alias):
                self.assertEqual(name_tokens(alias), ('fetch', 'url'))

    def test_different_behaviour_words_stay_apart(self):
        self.assertNotEqual(name_tokens('get_document'), name_tokens('delete_document'))

    def test_noise_only_name_is_empty(self):
        self.assertEqual(name_tokens('adapter_v2'), ())


class DescriptionNormalisation(unittest.TestCase):
    def test_case_and_punctuation_ignored(self):
        self.assertEqual(normalized_description('Delete a document by id.'),
                         normalized_description('  delete A document, by ID '))

    def test_null_and_empty_never_link(self):
        self.assertIsNone(normalized_description(None))
        self.assertIsNone(normalized_description(' ... '))


class SchemaAndSignature(unittest.TestCase):
    S1 = {'type': 'object', 'properties': {'url': {'type': 'string', 'description': 'A'}}, 'required': ['url'],
          'additionalProperties': False}
    S2 = {'type': 'object', 'properties': {'URL': {'type': 'string', 'description': 'different text'}},
          'required': ['URL'], 'additionalProperties': False}

    def test_fingerprint_ignores_text_and_case(self):
        self.assertEqual(schema_fingerprint(self.S1), schema_fingerprint(self.S2))

    def test_fingerprint_sees_types(self):
        s3 = {**self.S1, 'properties': {'url': {'type': 'number'}}}
        self.assertNotEqual(schema_fingerprint(self.S1), schema_fingerprint(s3))

    def test_signature_depends_on_effect_profile(self):
        a = template_signature(self.S1, ['url'], ['http_get'], 'controlled_execution')
        b = template_signature(self.S1, ['url'], ['send:http'], 'controlled_execution')
        self.assertNotEqual(a, b)
        self.assertEqual(a, template_signature(self.S2, ['url'], ['http_get'], 'controlled_execution'))

    def test_effect_profile_tokens(self):
        trace = [{'event': 'store_read', 'view': 'metadata'}, {'event': 'store_write', 'mode': 'append'},
                 {'event': 'send', 'channel': 'email'}, {'event': 'send', 'channel': 'email'},
                 {'event': 'opaque_invoked'}]
        self.assertEqual(effect_profile_from_trace(trace),
                         ['store_read:metadata', 'store_write:append', 'send:email', 'opaque_invoked'])


if __name__ == '__main__':
    unittest.main()
