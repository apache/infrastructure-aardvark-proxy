# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import string
import nltk
import typing
import requests
import json

MINIMUM_NUMBER_OF_WORDS = 9  # We need at least SOME words to safely classify this


class BayesScanner:
    """ A very naïve spam scanner """

    def reload_spamdb(self):
        """ This is how corpus/spamdb.json was built..."""
        spamdb = requests.get(
            "https://raw.githubusercontent.com/zmohammad01/nlc-email-spam/master/data/Email-testingdata.json"
        ).json()
        for corpus in spamdb:
            words = self.tokenify(corpus["Text"])
            if corpus["Class"] == "spam":
                self.spam_words.extend(words)
            else:
                self.ham_words.extend(words)
        spamdb = json.loads(
            requests.get(
                "https://raw.githubusercontent.com/cdimascio/watson-nlc-spam/master/data/SpamHam-Train.json"
            ).text[:-2]
        )
        for corpus in spamdb["training_data"]:
            words = self.tokenify(corpus["text"])
            if "spam" in corpus["classes"]:
                self.spam_words.extend(words)
            else:
                self.ham_words.extend(words)
        with open("corpus/spamdb.json", "w") as f:
            json.dump({"spam": self.spam_words, "ham": self.ham_words}, f)
            f.close()

    def __init__(self):
        self.punctuation = string.punctuation
        self.ham_words: typing.List[str] = []
        self.spam_words: typing.List[str] = []

        nltk.download("stopwords")
        nltk.download("punkt")
        self.stopwords = nltk.corpus.stopwords.words("english")

        spamdb = json.load(open("corpus/spamdb.json"))
        self.spam_words = spamdb["spam"]
        self.ham_words = spamdb["ham"]
        print(
            "Naïve spam scanner loaded %u hams and %u spams"
            % (len(self.ham_words), len(self.spam_words))
        )

    def tokenify(self, text: str):
        """ Cut out punctuation and return only meaningful words (not stopwords)"""
        remove_punct = "".join(
            [word.lower() for word in text if word not in self.punctuation]
        )
        tokenize = nltk.tokenize.word_tokenize(remove_punct)
        tokens = [word for word in tokenize if word not in self.stopwords]
        return tokens

    def count_words(self, words: typing.List[str]):
        ham_count = 0
        spam_count = 0
        for word in words:
            ham_count += self.ham_words.count(word)
            spam_count += self.spam_words.count(word)
        return ham_count, spam_count

    def naive_result(self, ham: int, spam: int):
        """ Calculate the naïve result. 0 means ham, 50 means I don't know, 100 means spam"""
        if ham > spam:
            return round(100 - (ham / (ham + spam) * 100))
        elif ham < spam and spam >= MINIMUM_NUMBER_OF_WORDS/2:
            return round(spam / (ham + spam) * 100)
        return 50

    def scan_text(self, text: str):
        text_processed = self.tokenify(text)
        if len(text_processed) > MINIMUM_NUMBER_OF_WORDS:
            h, s = self.count_words(text_processed)
            result = self.naive_result(h, s)
        else:
            result = 0
        return result
