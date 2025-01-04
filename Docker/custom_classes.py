import sklearn
from sklearn.base import BaseEstimator, TransformerMixin

class SampleSubsetSelector(BaseEstimator, TransformerMixin):
    def __init__(self, max_train_samples=6000):
        self.max_train_samples = max_train_samples
        self.is_train = True  # Default to training mode

    def fit(self, X, y=None):
        return self  # No fitting necessary for this transformer

    def transform(self, X, y=None):
        if self.is_train and y is not None:
            if len(X) > self.max_train_samples:
                X, _, y, _ = train_test_split(X, y, train_size=self.max_train_samples, stratify=y, random_state=22)       
        return (X, y) if y is not None else X

    def set_is_train(self, is_train=True):
        self.is_train = is_train