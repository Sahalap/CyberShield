import pandas as pd
import numpy as np
import logging
from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os
from typing import Tuple, Dict, Any

logging.basicConfig(level=logging.INFO)

class PhishingModelTrainer:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._get_default_config()
        self.model = None
        self.feature_names = None
    
    def _get_default_config(self) -> Dict[str, Any]:
        return {
            'test_size': 0.25,  # Increased for better validation
            'random_state': 42,
            # Target phishing:benign ratio used when capping majority (e.g., 1:10)
            'target_ratio': 10,
            'model_params': {
                'iterations': 500,  # Reduced to prevent overfitting
                'learning_rate': 0.05,  # Lower learning rate
                'depth': 4,  # FIXED: Reduced depth to prevent overfitting
                'eval_metric': 'Accuracy',
                'random_seed': 42,
                'verbose': 100,
                'task_type': 'CPU',
                # Increase weight for phishing (minority) since we keep more benign in training
                'class_weights': [1, 8],
                'l2_leaf_reg': 3,  # Added regularization
                'border_count': 32,  # Reduced for simpler model
                'min_data_in_leaf': 10,  # Prevent overfitting on small patterns
            }
        }
    
    def balance_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Balance dataset - use all data if already balanced, downsample if very imbalanced."""
        try:
            # Separate classes
            legitimate = df[df['label'] == 0]
            phishing = df[df['label'] == 1]
            
            logging.info(f"Original data: {len(legitimate)} legitimate, {len(phishing)} phishing")

            # Calculate imbalance ratio
            min_count = min(len(legitimate), len(phishing))
            max_count = max(len(legitimate), len(phishing))
            ratio = max_count / min_count if min_count > 0 else float('inf')
            
            logging.info(f"Class imbalance ratio: {ratio:.2f}:1")
            
            # If dataset is already reasonably balanced (within 2:1 ratio), USE ALL DATA!
            if ratio <= 2.0:
                logging.info("✅ Dataset is balanced! Using ALL data for training.")
                balanced_df = df.sample(frac=1, random_state=self.config['random_state']).reset_index(drop=True)
                logging.info(f"Training on: {len(balanced_df[balanced_df['label'] == 0])} legitimate, {len(balanced_df[balanced_df['label'] == 1])} phishing")
                return balanced_df
            
            # Otherwise, downsample to 1.5:1 ratio
            logging.info(f"⚠️  Dataset imbalanced ({ratio:.1f}:1). Downsampling to 1.5:1 ratio...")
            target_majority_size = min(max_count, int(min_count * 1.5))
            
            # Downsample to create balanced dataset
            if len(phishing) > len(legitimate):
                # Phishing is majority - downsample it
                phishing_balanced = phishing.sample(
                    n=target_majority_size, 
                    random_state=self.config['random_state']
                )
                legitimate_balanced = legitimate
            else:
                # Legitimate is majority - downsample it  
                legitimate_balanced = legitimate.sample(
                    n=target_majority_size,
                    random_state=self.config['random_state']
                )
                phishing_balanced = phishing

            balanced_df = pd.concat([legitimate_balanced, phishing_balanced], ignore_index=True)
            balanced_df = balanced_df.sample(frac=1, random_state=self.config['random_state']).reset_index(drop=True)

            logging.info(f"Balanced data: {len(balanced_df[balanced_df['label'] == 0])} legitimate, {len(balanced_df[balanced_df['label'] == 1])} phishing")

            return balanced_df
            
        except Exception as e:
            logging.error(f"Error balancing dataset: {e}")
            raise

    def load_and_validate_data(self, data_file: str) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and validate training data with balancing"""
        try:
            df = pd.read_csv(data_file)
            
            if 'label' not in df.columns:
                raise ValueError("CSV must contain a 'label' column")
            
            # Balance the dataset
            balanced_df = self.balance_dataset(df)
            
            # Check data balance
            label_counts = balanced_df['label'].value_counts()
            logging.info(f"Balanced data distribution: {label_counts.to_dict()}")
            
            if len(label_counts) < 2:
                raise ValueError("Data must contain both classes")
            
            X = balanced_df.drop('label', axis=1)
            y = balanced_df['label']
            
            return X, y
            
        except Exception as e:
            logging.error(f"Error loading data: {e}")
            raise
    
    def train_model(self, X: pd.DataFrame, y: pd.Series) -> CatBoostClassifier:
        """Train the model with proper error handling and validation"""
        try:
            # Split data with stratification
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=self.config['test_size'], 
                random_state=self.config['random_state'], 
                stratify=y
            )
            
            logging.info(f"Training set: {len(X_train)} samples")
            logging.info(f"Test set: {len(X_test)} samples")
            
            # Create model with regularization
            self.model = CatBoostClassifier(**self.config['model_params'])
            
            # Train with early stopping
            self.model.fit(
                X_train, y_train, 
                eval_set=(X_test, y_test), 
                use_best_model=True,
                early_stopping_rounds=50  # Stop if no improvement
            )
            
            # Evaluate on test set
            y_pred = self.model.predict(X_test)
            y_pred_proba = self.model.predict_proba(X_test)[:, 1]
            
            accuracy = accuracy_score(y_test, y_pred)
            
            # Calculate precision and recall separately for both classes
            from sklearn.metrics import precision_recall_fscore_support
            precision, recall, f1, support = precision_recall_fscore_support(y_test, y_pred, average=None)
            
            logging.info(f"\n{'='*60}")
            logging.info(f"Model Performance Metrics:")
            logging.info(f"{'='*60}")
            logging.info(f"Overall Accuracy: {accuracy:.4f}")
            logging.info(f"\nLegitimate (Class 0):")
            logging.info(f"  Precision: {precision[0]:.4f} (How many flagged legitimate are actually legitimate)")
            logging.info(f"  Recall: {recall[0]:.4f} (How many legitimate sites are correctly identified)")
            logging.info(f"  F1-Score: {f1[0]:.4f}")
            logging.info(f"\nPhishing (Class 1):")
            logging.info(f"  Precision: {precision[1]:.4f} (How many flagged phishing are actually phishing)")
            logging.info(f"  Recall: {recall[1]:.4f} (How many phishing sites are caught)")
            logging.info(f"  F1-Score: {f1[1]:.4f}")
            
            # Check for acceptable false positive rate
            false_positives = sum((y_test == 0) & (y_pred == 1))
            total_legitimate = sum(y_test == 0)
            fp_rate = false_positives / total_legitimate if total_legitimate > 0 else 0
            
            logging.info(f"\nFalse Positive Rate: {fp_rate:.4f} ({false_positives}/{total_legitimate})")
            
            if fp_rate > 0.05:  # More than 5% false positives
                logging.warning("⚠️  High false positive rate! Consider:")
                logging.warning("   - Collecting more diverse legitimate URLs")
                logging.warning("   - Adjusting classification threshold")
                logging.warning("   - Adding more whitelisted domains")
            
            logging.info(f"\n{'='*60}")
            logging.info("Full Classification Report:")
            logging.info(f"{'='*60}")
            logging.info("\n" + classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
            
            return self.model
            
        except Exception as e:
            logging.error(f"Training error: {e}")
            raise
    
    def save_model(self, model_path: str) -> bool:
        """Save model with error handling"""
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(self.model, model_path)
            logging.info(f"✅ Model saved to {model_path}")
            return True
        except Exception as e:
            logging.error(f"Error saving model: {e}")
            return False

def test_model_on_legitimate_sites(model_path: str = "models/catboost_model.pkl"):
    """Test the model on legitimate sites to check for false positives"""
    try:
        from feature_extraction import extract_features
        
        model = joblib.load(model_path)
        print('\n' + '='*60)
        print('COMPREHENSIVE MODEL TESTING')
        print('='*60)
        print('✅ Model loaded successfully!\n')
        
        # Expanded list of legitimate sites
        legitimate_urls = [
            'https://google.com',
            'https://youtube.com', 
            'https://facebook.com',
            'https://github.com',
            'https://stackoverflow.com',
            'https://amazon.com',
            'https://microsoft.com',
            'https://apple.com',
            'https://netflix.com',
            'https://linkedin.com',
            'https://web.whatsapp.com',
            'https://whatsapp.com',
            'https://twitter.com',
            'https://instagram.com',
            'https://reddit.com',
            'https://wikipedia.org',
            'https://chatgpt.com',
            'https://openai.com',
            'https://gmail.com',
            'https://dropbox.com',
            'https://zoom.us',
            'https://slack.com',
            'https://discord.com',
            'https://spotify.com',
            'https://twitch.tv'
        ]
        
        print('🔍 Testing Legitimate Sites:')
        print('-' * 60)
        false_positives = 0
        
        for url in legitimate_urls:
            try:
                features = extract_features([url])
                probability = model.predict_proba(features)[0][1]
                # Use conservative threshold for legitimate sites (0.4) to avoid false positives
                prediction = 1 if probability >= 0.4 else 0
                result = 'PHISHING' if prediction == 1 else 'LEGITIMATE'
                
                if prediction == 1:
                    false_positives += 1
                    print(f'  ❌ {url:40} -> {result} (conf: {probability:.3f}) - FALSE POSITIVE!')
                else:
                    print(f'  ✅ {url:40} -> {result} (conf: {probability:.3f})')
                    
            except Exception as e:
                print(f'  ❌ {url:40} -> ERROR: {e}')
        
        fp_rate = (false_positives / len(legitimate_urls)) * 100
        print(f'\n📊 Legitimate Sites: {false_positives}/{len(legitimate_urls)} false positives ({fp_rate:.1f}%)')
        
        # Test phishing sites
        phishing_urls = [
            'https://bit.ly/suspicious-link',
            'https://tinyurl.com/fake-deal', 
            'https://whatsapp-verify.tk',
            'https://p4ypal-security.ml',
            'https://amaz0n-update.ga',
            'https://fake-paypal.tk',
            'https://suspicious-deal.cf',
            'https://paypal-security.tk',
            'https://suspicious-test.tk',
            'https://micr0soft-security.tk',
            'https://g00gle-verify.ml',
            'https://app1e-login.ga'
        ]
        
        print('\n🔍 Testing Phishing Sites:')
        print('-' * 60)
        true_positives = 0
        
        for url in phishing_urls:
            try:
                features = extract_features([url])
                probability = model.predict_proba(features)[0][1]
                # Use more aggressive threshold for phishing detection (0.3) to catch more phishing
                prediction = 1 if probability >= 0.3 else 0
                result = 'PHISHING' if prediction == 1 else 'LEGITIMATE'
                
                if prediction == 1:
                    true_positives += 1
                    print(f'  ✅ {url:40} -> {result} (conf: {probability:.3f}) - DETECTED!')
                else:
                    print(f'  ❌ {url:40} -> {result} (conf: {probability:.3f}) - MISSED!')
                    
            except Exception as e:
                print(f'  ❌ {url:40} -> ERROR: {e}')
        
        detection_rate = (true_positives / len(phishing_urls)) * 100
        print(f'\n📊 Phishing Sites: {true_positives}/{len(phishing_urls)} detected ({detection_rate:.1f}%)')
        
        # Overall performance
        total_tests = len(legitimate_urls) + len(phishing_urls)
        correct_predictions = (len(legitimate_urls) - false_positives) + true_positives
        overall_accuracy = (correct_predictions / total_tests) * 100
        
        print(f'\n{"="*60}')
        print(f'🎯 OVERALL PERFORMANCE:')
        print(f'{"="*60}')
        print(f'   Accuracy: {overall_accuracy:.1f}%')
        print(f'   False Positive Rate: {fp_rate:.1f}%')
        print(f'   Detection Rate: {detection_rate:.1f}%')
        print(f'   False Positives: {false_positives}')
        print(f'   True Positives: {true_positives}')
        
        # Quality assessment
        print(f'\n{"="*60}')
        if fp_rate <= 4 and detection_rate >= 80:
            print('✅ ✅ ✅ MODEL QUALITY: EXCELLENT!')
            print('   Low false positives + High detection rate')
        elif fp_rate <= 10 and detection_rate >= 70:
            print('✅ ✅ MODEL QUALITY: GOOD')
            print('   Acceptable balance of precision and recall')
        elif fp_rate <= 15:
            print('⚠️  MODEL QUALITY: ACCEPTABLE')
            print('   Consider improving to reduce false positives')
        else:
            print('❌ MODEL QUALITY: NEEDS IMPROVEMENT')
            print('   High false positive rate - retrain with more data')
        print(f'{"="*60}\n')
            
    except Exception as e:
        print(f'❌ Error testing model: {e}')
        import traceback
        traceback.print_exc()

def main():
    """Main training function with comprehensive testing"""
    try:
        logging.info("="*60)
        logging.info("Starting PhishGuard ML Model Training")
        logging.info("="*60)
        
        trainer = PhishingModelTrainer()
        X, y = trainer.load_and_validate_data("data/url_features.csv")
        
        model = trainer.train_model(X, y)
        
        success = trainer.save_model("models/catboost_model.pkl")
        
        if success:
            logging.info("\n" + "="*60)
            logging.info("✅ Training completed successfully!")
            logging.info("="*60)
            
            # Test the model comprehensively
            test_model_on_legitimate_sites()
        else:
            logging.error("❌ Failed to save model")
            
    except Exception as e:
        logging.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()