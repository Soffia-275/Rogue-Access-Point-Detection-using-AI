# model.py
import pandas as pd
import numpy as np
import joblib
import warnings
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Conv1D, Flatten, LSTM, Reshape
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping

warnings.filterwarnings('ignore')

class EvilTwinModel:
    def __init__(self, model_type='dense'):
        self.traffic_model = None
        self.traffic_scaler = None
        self.model_type = model_type  # 'dense', 'cnn', 'lstm'

    def create_model(self, input_dim):
        """Create model: dense, cnn, or lstm"""
        if self.model_type == 'dense':
            model = Sequential([
                Dense(64, activation='relu', input_shape=(input_dim,)),
                Dropout(0.3),
                Dense(32, activation='relu'),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
        elif self.model_type == 'cnn':
            model = Sequential([
                Reshape((input_dim, 1), input_shape=(input_dim,)),
                Conv1D(32, kernel_size=3, activation='relu'),
                Conv1D(16, kernel_size=3, activation='relu'),
                Flatten(),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
        elif self.model_type == 'lstm':
            model = Sequential([
                Reshape((input_dim, 1), input_shape=(input_dim,)),
                LSTM(32, activation='tanh', return_sequences=True),
                LSTM(16, activation='tanh'),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
        else:
            raise ValueError("Invalid model_type. Choose 'dense', 'cnn', or 'lstm'.")
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        return model

    def load_small_dataset(self):
        print(" Loading small dataset for fast training...")
        try:
            df = pd.read_csv('data/cic_evil_twin_processed.csv')
            print(f"Loaded CIC dataset: {len(df)} samples")
        except:
            try:
                df = pd.read_csv('data/unsw_evil_twin_processed.csv')
                print(f"Loaded UNSW dataset: {len(df)} samples")
            except Exception as e:
                print(f"Could not load any dataset: {e}")
                return None
        if len(df) > 2000:
            df = df.sample(n=10000, random_state=42)
            print(f"Using 2000 samples for fast training")
        return df

    def clean_data(self, X):
        print("🧹 Cleaning data (removing infinity/large values)...")
        X_clean = X.replace([np.inf, -np.inf], np.nan)
        inf_count = (X == np.inf).sum().sum() + (X == -np.inf).sum().sum()
        nan_count = X_clean.isna().sum().sum()
        if inf_count > 0: print(f"   Found {inf_count} infinite values")
        if nan_count > 0: print(f"   Found {nan_count} NaN values after cleaning")
        for col in X_clean.columns:
            col_median = X_clean[col].median()
            X_clean[col] = X_clean[col].fillna(col_median)
            upper_limit = X_clean[col].quantile(0.999)
            lower_limit = X_clean[col].quantile(0.001)
            if np.isfinite(upper_limit) and np.isfinite(lower_limit):
                X_clean[col] = np.clip(X_clean[col], lower_limit, upper_limit)
        return X_clean

    def preprocess_fast(self, df):
        print("🔧 Fast preprocessing...")
        target_column = None
        for col in ['is_evil_twin', 'Label', 'label', 'is_malicious', 'target']:
            if col in df.columns:
                target_column = col
                break
        if target_column is None:
            for col in df.columns:
                if df[col].dtype in [np.int64, np.float64] and df[col].nunique() <= 10:
                    target_column = col
                    break
        if target_column is None:
            print("No target column found!")
            return None, None, None
        print(f"Target column: {target_column}")
        if df[target_column].dtype == 'object':
            y = np.array([0 if 'BENIGN' in str(label).upper() or 'NORMAL' in str(label).upper() else 1 
                          for label in df[target_column]])
        else:
            y = df[target_column].values
            if len(np.unique(y)) > 2: y = (y > 0).astype(int)
        print(f"Class distribution: {np.unique(y, return_counts=True)}")
        exclude_cols = [target_column, 'attack_cat', 'id', 'ssid', 'timestamp', 'time', 'date']
        feature_cols = [col for col in df.columns if col not in exclude_cols and df[col].dtype in [np.int64, np.float64]]
        if not feature_cols:
            feature_cols = [col for col in df.columns if col not in exclude_cols]
            for col in feature_cols:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            df[feature_cols] = df[feature_cols].fillna(0)
        X = df[feature_cols]
        X_clean = self.clean_data(X)
        print(f"Using {len(feature_cols)} features")
        return X_clean, y, feature_cols

    def train_fast(self):
        print("STARTING FAST TRAINING...")
        try:
            df = self.load_small_dataset()
            if df is None: return False, "Failed to load dataset"
            X, y, features = self.preprocess_fast(df)
            if X is None: return False, "Preprocessing failed"
            if len(X) < 100: return False, f"Not enough data after cleaning: {len(X)} samples"
            print(f"Data ready: {X.shape[0]} samples, {X.shape[1]} features")
            print("Scaling features...")
            self.traffic_scaler = StandardScaler()
            try:
                X_scaled = self.traffic_scaler.fit_transform(X)
            except Exception as e:
                print(f"Standard scaling failed, using RobustScaler: {e}")
                from sklearn.preprocessing import RobustScaler
                self.traffic_scaler = RobustScaler()
                X_scaled = self.traffic_scaler.fit_transform(X)
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42, stratify=y
            )
            print(f"Training: {X_train.shape[0]}, Test: {X_test.shape[0]}")
            self.traffic_model = self.create_model(X_train.shape[1])
            # reshape for CNN/LSTM
            if self.model_type in ['cnn','lstm']:
                X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
                X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
            print("Training model ")
            history = self.traffic_model.fit(
                X_train, y_train,
                epochs=50,
                batch_size=32,
                validation_data=(X_test, y_test),
                verbose=1,
                callbacks=[EarlyStopping(patience=3, restore_best_weights=True)]
            )
            test_loss, test_accuracy = self.traffic_model.evaluate(X_test, y_test, verbose=0)
            print(f"Training complete! Accuracy: {test_accuracy:.4f}")
            self.traffic_model.save('traffic_model.h5')
            joblib.dump(self.traffic_scaler, 'traffic_scaler.pkl')
            print("Models saved: traffic_model.h5, traffic_scaler.pkl")
            return True, f"Fast training complete! Accuracy: {test_accuracy:.4f}"
        except Exception as e:
            print(f"Training failed with error: {e}")
            return False, f"Training error: {e}"

class EvilTwinDetector:
    def __init__(self):
        try:
            self.traffic_model = tf.keras.models.load_model('traffic_model.h5')
            self.traffic_scaler = joblib.load('traffic_scaler.pkl')
            self.model_loaded = True
            print("AI Model loaded successfully")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model_loaded = False

    def analyze_network_traffic(self, feature_dict):
        if not self.model_loaded:
            return {'error': "Model not trained. Please train first."}
        try:
            feature_df = pd.DataFrame([feature_dict])
            for feature in self.traffic_scaler.feature_names_in_:
                if feature not in feature_df.columns:
                    feature_df[feature] = 0
            feature_df = feature_df[self.traffic_scaler.feature_names_in_].fillna(0)
            for col in feature_df.columns:
                feature_df[col] = pd.to_numeric(feature_df[col], errors='coerce')
            feature_df = feature_df.replace([np.inf, -np.inf], 0)
            feature_df = feature_df.fillna(0)
            # reshape for CNN/LSTM
            feature_scaled = self.traffic_scaler.transform(feature_df)
            if len(self.traffic_model.input_shape) == 3:
                feature_scaled = feature_scaled.reshape(feature_scaled.shape[0], feature_scaled.shape[1], 1)
            prediction_prob = self.traffic_model.predict(feature_scaled, verbose=0)[0][0]
            if prediction_prob > 0.7:
                is_evil_twin = True
                safety_score = (1 - prediction_prob) * 100
            elif prediction_prob < 0.3:
                is_evil_twin = False
                safety_score = (1 - prediction_prob) * 100
            else:
                is_evil_twin = prediction_prob > 0.5
                safety_score = 50
            if is_evil_twin:
                if safety_score < 30:
                    recommendation = "EVIL TWIN DETECTED! Disconnect immediately!"
                else:
                    recommendation = "Suspicious network detected."
            else:
                if safety_score >= 80:
                    recommendation = "Network appears safe."
                else:
                    recommendation = "Network shows minor anomalies."
            return {
                'safety_score': round(safety_score, 2),
                'safety_level': "SAFE" if safety_score >= 70 else "CAUTION" if safety_score >= 50 else "🔴 UNSAFE",
                'recommendation': recommendation,
                'is_evil_twin': bool(is_evil_twin),
                'probability_evil_twin': f"{prediction_prob:.2%}",
                'probability_legitimate': f"{(1-prediction_prob):.2%}"
            }
        except Exception as e:
            return {'error': f"Analysis failed: {e}"}

def train_model_standalone(model_type='dense'):
    print("=" * 50)
    print(f"EVIL TWIN DETECTOR - FAST TRAINING ({model_type.upper()})")
    print("=" * 50)
    trainer = EvilTwinModel(model_type=model_type)
    success, message = trainer.train_fast()
    if success:
        print("\nTRAINING SUCCESSFUL!")
        print("\nNow you can run: streamlit run app.py")
    else:
        print(f"\nTRAINING FAILED: {message}")

if __name__ == "__main__":
    # Change 'dense' to 'cnn' or 'lstm' as needed
    train_model_standalone(model_type='dense')
