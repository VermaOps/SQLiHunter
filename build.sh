#!/bin/bash
# Clean Build Script for SQLi Hunter v1.0.0 with AI Integration

set -e

echo "=========================================="
echo "SQLi Hunter v1.0.0 Build Script (with AI)"
echo "=========================================="
echo ""

# Configuration - MODIFY THESE PATHS AS NEEDED
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
BUILD_DIR="$SCRIPT_DIR/build"
LIB_DIR="$SCRIPT_DIR/lib"
OUTPUT_JAR="$SCRIPT_DIR/SQLiHunter.jar"

# Gson library (required for JSON parsing in ParameterExtractor.java)
GSON_VERSION="2.10.1"
GSON_JAR="$LIB_DIR/gson-$GSON_VERSION.jar"

# Burp JAR location (update for your system)
# macOS defaults:
BURP_JAR="/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar"
if [ ! -f "$BURP_JAR" ]; then
    BURP_JAR="/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar"
fi

# Linux example (uncomment and modify as needed):
# BURP_JAR="/opt/BurpSuitePro/burpsuite_pro.jar"

# Windows example (for Git Bash / WSL):
# BURP_JAR="/c/Program Files/BurpSuitePro/burpsuite_pro.jar"

# Check if Burp JAR exists
if [ ! -f "$BURP_JAR" ]; then
    echo "ERROR: Burp Suite JAR not found!"
    echo "Expected at: $BURP_JAR"
    echo ""
    echo "Please set BURP_JAR environment variable or edit this script:"
    echo "  export BURP_JAR=/path/to/your/burpsuite.jar"
    echo ""
    read -p "Enter Burp JAR path: " user_burp_jar
    if [ -f "$user_burp_jar" ]; then
        BURP_JAR="$user_burp_jar"
    else
        echo "ERROR: Invalid path: $user_burp_jar"
        exit 1
    fi
fi

echo "[1/9] Checking prerequisites..."
echo "  Java version:"
java -version 2>&1 | head -1
echo "  Burp JAR: $BURP_JAR"
echo "  Source directory: $SRC_DIR"

# Check source structure
echo ""
echo "[2/9] Checking source directory structure..."

if [ ! -d "$SRC_DIR" ]; then
    echo "  ✗ Source directory not found: $SRC_DIR"
    exit 1
fi

# Check main package
if [ ! -d "$SRC_DIR/main" ]; then
    echo "  ✗ main package not found: $SRC_DIR/main"
    exit 1
fi

# Check ai package
if [ ! -d "$SRC_DIR/ai" ]; then
    echo "  ✗ ai package not found: $SRC_DIR/ai"
    echo "  AI integration requires src/ai/ directory with provider classes"
    exit 1
fi

echo "  ✓ Source structure:"
echo "    - main/: $(find "$SRC_DIR/main" -name "*.java" | wc -l) Java files"
echo "    - ai/:   $(find "$SRC_DIR/ai" -name "*.java" | wc -l) Java files"

# Count all Java files
MAIN_JAVA_COUNT=$(find "$SRC_DIR/main" -name "*.java" 2>/dev/null | wc -l)
AI_JAVA_COUNT=$(find "$SRC_DIR/ai" -name "*.java" 2>/dev/null | wc -l)
TOTAL_JAVA_FILES=$((MAIN_JAVA_COUNT + AI_JAVA_COUNT))

if [ "$TOTAL_JAVA_FILES" -eq 0 ]; then
    echo "  ✗ No Java files found"
    exit 1
fi

echo "  ✓ Found $TOTAL_JAVA_FILES Java files total ($MAIN_JAVA_COUNT main + $AI_JAVA_COUNT ai)"

# List all Java files
echo ""
echo "[3/9] Java files found:"

echo "  main/ package:"
ls "$SRC_DIR/main"/*.java 2>/dev/null | xargs basename -a 2>/dev/null | sed 's/^/    /' | sort

echo "  ai/ package:"
ls "$SRC_DIR/ai"/*.java 2>/dev/null | xargs basename -a 2>/dev/null | sed 's/^/    /' | sort

# Check critical files with proper categories
echo ""
echo "[4/9] Checking critical files by category..."

# ============================================================================
# CATEGORY 1: Core Extension Entry Point
# ============================================================================
EXTENSION_FILES=(
    "SQLiHunterExtension.java"
)

# ============================================================================
# CATEGORY 2: UI Layer Components
# ============================================================================
UI_FILES=(
    "MainTab.java"
    "ResultsPanel.java"
    "SettingsPanel.java"
    "ApiTrafficPanel.java"
)

# ============================================================================
# CATEGORY 3: Traffic Capture & Management
# ============================================================================
TRAFFIC_FILES=(
    "ApiTrafficEntry.java"
    "ApiTrafficModel.java"
    "ProxyResponseHighlighter.java"
    "RepeaterCaptureHandler.java"
)

# ============================================================================
# CATEGORY 4: Scanning Engine Core
# ============================================================================
SCAN_ENGINE_FILES=(
    "ScanEngine.java"
    "ParameterExtractor.java"
    "PayloadBuilder.java"
    "RequestMutator.java"
    "ResponseAnalyzer.java"
)

# ============================================================================
# CATEGORY 5: Data Models
# ============================================================================
MODEL_FILES=(
    "ScanConfig.java"
    "ScanFinding.java"
    "ResultsModel.java"
)

# ============================================================================
# CATEGORY 6: Utilities & Helpers
# ============================================================================
UTILITY_FILES=(
    "VersionManager.java"
)

# ============================================================================
# CATEGORY 7: Context Menu Integration
# ============================================================================
MENU_FILES=(
    "SQLiContextMenuProvider.java"
)

# ============================================================================
# CATEGORY 8: AI Provider Layer (ai package)
# ============================================================================
AI_FILES=(
    "AIProvider.java"
    "AIResponse.java"
    "OllamaProvider.java"
    "OpenAIProvider.java"
    "ClaudeProvider.java"
    "ConversationHistory.java"
)

# ============================================================================
# Combine all required files for validation
# ============================================================================
MAIN_CRITICAL_FILES=(
    "${EXTENSION_FILES[@]}"
    "${UI_FILES[@]}"
    "${TRAFFIC_FILES[@]}"
    "${SCAN_ENGINE_FILES[@]}"
    "${MODEL_FILES[@]}"
    "${UTILITY_FILES[@]}"
    "${MENU_FILES[@]}"
)

AI_REQUIRED_FILES=("${AI_FILES[@]}")

total_main_expected=${#MAIN_CRITICAL_FILES[@]}
total_ai_expected=${#AI_REQUIRED_FILES[@]}

echo "    Expected files by category:"
echo ""
echo "    Extension (${#EXTENSION_FILES[@]}): ${EXTENSION_FILES[*]}"
echo ""
echo "    UI Layer (${#UI_FILES[@]}): ${UI_FILES[*]}"
echo ""
echo "    Traffic Capture (${#TRAFFIC_FILES[@]}): ${TRAFFIC_FILES[*]}"
echo ""
echo "    Scan Engine (${#SCAN_ENGINE_FILES[@]}): ${SCAN_ENGINE_FILES[*]}"
echo ""
echo "    Data Models (${#MODEL_FILES[@]}): ${MODEL_FILES[*]}"
echo ""
echo "    Utilities (${#UTILITY_FILES[@]}): ${UTILITY_FILES[*]}"
echo ""
echo "    Context Menu (${#MENU_FILES[@]}): ${MENU_FILES[*]}"
echo ""
echo "    AI Providers (${#AI_FILES[@]}): ${AI_FILES[*]}"
echo ""

echo "  Checking main/ package (${#MAIN_CRITICAL_FILES[@]} files across 7 categories):"

# Check main package files by category
missing_main=()
found_main=0

# Helper function to check files in a category
check_category() {
    local category_name="$1"
    shift
    local files=("$@")
    local category_missing=()
    
    for file in "${files[@]}"; do
        if [ ! -f "$SRC_DIR/main/$file" ]; then
            missing_main+=("main/$file")
            category_missing+=("$file")
            echo "    ✗ [$category_name] Missing: $file"
        else
            echo "    ✓ [$category_name] Found: $file"
            ((found_main++))
        fi
    done
    
    if [ ${#category_missing[@]} -gt 0 ]; then
        echo "      └─ $category_name: ${#category_missing[@]} missing"
    fi
}

echo ""
echo "  --- main/ package validation ---"

# Check each category
check_category "Extension" "${EXTENSION_FILES[@]}"
check_category "UI" "${UI_FILES[@]}"
check_category "Traffic" "${TRAFFIC_FILES[@]}"
check_category "ScanEngine" "${SCAN_ENGINE_FILES[@]}"
check_category "Models" "${MODEL_FILES[@]}"
check_category "Utilities" "${UTILITY_FILES[@]}"
check_category "Menu" "${MENU_FILES[@]}"

echo ""
echo "  Checking ai/ package (${#AI_REQUIRED_FILES[@]} files):"
missing_ai=()
found_ai=0

for file in "${AI_REQUIRED_FILES[@]}"; do
    if [ ! -f "$SRC_DIR/ai/$file" ]; then
        missing_ai+=("ai/$file")
        echo "    ✗ Missing: $file"
    else
        echo "    ✓ Found: $file"
        ((found_ai++))
    fi
done

echo ""
echo "  Summary:"
echo "    main/: $found_main of $total_main_expected files found (${#MAIN_CRITICAL_FILES[@]} total)"
echo "    ai/:   $found_ai of $total_ai_expected files found"

# Show per-category counts
echo ""
echo "  Per-category summary:"
echo "    Extension:   ${#EXTENSION_FILES[@]}/${#EXTENSION_FILES[@]} files"
echo "    UI:          ${#UI_FILES[@]}/${#UI_FILES[@]} files"
echo "    Traffic:     ${#TRAFFIC_FILES[@]}/${#TRAFFIC_FILES[@]} files"
echo "    ScanEngine:  ${#SCAN_ENGINE_FILES[@]}/${#SCAN_ENGINE_FILES[@]} files"
echo "    Models:      ${#MODEL_FILES[@]}/${#MODEL_FILES[@]} files"
echo "    Utilities:   ${#UTILITY_FILES[@]}/${#UTILITY_FILES[@]} files"
echo "    Menu:        ${#MENU_FILES[@]}/${#MENU_FILES[@]} files"
echo "    AI:          ${#AI_FILES[@]}/${#AI_FILES[@]} files"

# Check for missing files
ALL_MISSING=("${missing_main[@]}" "${missing_ai[@]}")
if [ ${#ALL_MISSING[@]} -gt 0 ]; then
    echo ""
    echo "  ERROR: Missing ${#ALL_MISSING[@]} required files:"
    printf "    %s\n" "${ALL_MISSING[@]}"
    echo ""
    echo "  Build cannot proceed without all files"
    exit 1
else
    echo "  ✓ All ${#MAIN_CRITICAL_FILES[@]} main + ${#AI_REQUIRED_FILES[@]} AI files found"
fi

# Create directories
echo ""
echo "[5/9] Creating build directories..."
mkdir -p "$BUILD_DIR"
mkdir -p "$LIB_DIR"

# Download Gson library if not exists
echo ""
echo "[6/9] Downloading Gson library..."
if [ ! -f "$GSON_JAR" ]; then
    GSON_URL="https://repo1.maven.org/maven2/com/google/code/gson/gson/$GSON_VERSION/gson-$GSON_VERSION.jar"
    echo "  Downloading from: $GSON_URL"
    
    if command -v curl &> /dev/null; then
        curl -L -o "$GSON_JAR" "$GSON_URL"
    elif command -v wget &> /dev/null; then
        wget -O "$GSON_JAR" "$GSON_URL"
    else
        echo "  ✗ Need curl or wget to download Gson library"
        exit 1
    fi
    
    if [ $? -eq 0 ]; then
        echo "  ✓ Downloaded: $GSON_JAR"
    else
        echo "  ✗ Download failed"
        exit 1
    fi
else
    echo "  ✓ Gson library already exists: $GSON_JAR"
fi

# Compile
echo ""
echo "[7/9] Compiling Java source files..."
cd "$SCRIPT_DIR"

# Get all Java files
ALL_JAVA_FILES=$(find "$SRC_DIR" -name "*.java")

echo "  Compiling $TOTAL_JAVA_FILES files..."
echo "  Classpath: Burp JAR + Gson"

# Compile with classpath including Burp and Gson
javac -d "$BUILD_DIR" \
      -cp "$BURP_JAR:$GSON_JAR" \
      -Xlint:unchecked \
      $ALL_JAVA_FILES 2>&1 | tee "$SCRIPT_DIR/compile.log"

COMPILE_STATUS=$?

if [ $COMPILE_STATUS -eq 0 ]; then
    echo "  ✓ Compilation successful"
    echo "  Compiled classes in: $BUILD_DIR/"
    
    # Show compiled packages
    echo "  Compiled packages:"
    for dir in "$BUILD_DIR"/*; do
        if [ -d "$dir" ]; then
            class_count=$(find "$dir" -name "*.class" 2>/dev/null | wc -l)
            echo "    - $(basename "$dir")/: $class_count classes"
        fi
    done
else
    echo "  ✗ Compilation failed"
    echo ""
    echo "=== COMPILATION ERRORS ==="
    grep -A 2 -B 2 "error:" "$SCRIPT_DIR/compile.log" | head -50
    echo ""
    echo "See full log: $SCRIPT_DIR/compile.log"
    exit 1
fi

# Check for warnings
if [ -f "$SCRIPT_DIR/compile.log" ]; then
    WARNINGS=$(grep -c "warning:" "$SCRIPT_DIR/compile.log" 2>/dev/null || echo "0")
    if [ "$WARNINGS" -gt 0 ] 2>/dev/null; then
        echo "  ⚠️ Found $WARNINGS warnings (see compile.log)"
    fi
fi

# Package
echo ""
echo "[8/9] Packaging JAR..."

# Create JAR with all classes (preserve package structure)
cd "$BUILD_DIR"
jar -cf "$OUTPUT_JAR" main/*.class ai/*.class
cd "$SCRIPT_DIR"

echo "  ✓ Created base JAR with main and ai packages"

# Add Gson library classes
echo "  Adding Gson library..."
TEMP_DIR="$SCRIPT_DIR/temp_gson"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"
jar -xf "$GSON_JAR"
cd "$SCRIPT_DIR"

jar -uf "$OUTPUT_JAR" -C "$TEMP_DIR" com/

# Cleanup
rm -rf "$TEMP_DIR"

echo "  ✓ Added Gson library to JAR"

# Verify JAR contents
echo ""
echo "[9/9] Verifying JAR..."
JAR_SIZE=$(du -h "$OUTPUT_JAR" | cut -f1)
CLASS_COUNT=$(jar -tf "$OUTPUT_JAR" | grep "\.class$" | wc -l)

echo "  JAR file: $OUTPUT_JAR"
echo "  Size: $JAR_SIZE"
echo "  Total classes: $CLASS_COUNT"
echo ""
echo "  Package structure in JAR:"

# Show main package classes by category
echo "    - main/ ($MAIN_JAVA_COUNT source files):"
jar -tf "$OUTPUT_JAR" | grep "^main/.*\.class$" | sed 's/^/        /' | head -20
if [ $(jar -tf "$OUTPUT_JAR" | grep "^main/.*\.class$" | wc -l) -gt 20 ]; then
    echo "        ... and more"
fi

echo ""
echo "    - ai/ ($AI_JAVA_COUNT source files):"
jar -tf "$OUTPUT_JAR" | grep "^ai/.*\.class$" | sed 's/^/        /'

# Show Gson classes count
GSON_CLASSES=$(jar -tf "$OUTPUT_JAR" | grep "^com/google/gson" | wc -l)
echo ""
echo "    - com/google/gson/: $GSON_CLASSES classes (embedded)"

# Final check
if [ ! -f "$OUTPUT_JAR" ]; then
    echo "  ✗ JAR creation failed!"
    exit 1
fi

echo ""
echo "=========================================="
echo "BUILD SUCCESSFUL! 🎉"
echo "=========================================="
echo ""
echo "Output: $OUTPUT_JAR"
echo "Version: v1.0.0 with AI Integration"
echo ""
echo "Files compiled:"
echo "  - main/: $MAIN_JAVA_COUNT Java files → $(jar -tf "$OUTPUT_JAR" | grep "^main/.*\.class$" | wc -l) classes"
echo "  - ai/:   $AI_JAVA_COUNT Java files → $(jar -tf "$OUTPUT_JAR" | grep "^ai/.*\.class$" | wc -l) classes"
echo "  - Total: $TOTAL_JAVA_FILES files → $CLASS_COUNT classes (including Gson)"
echo ""
echo "Categories included:"
echo "  ✓ Extension    (1 file)"
echo "  ✓ UI Layer     (4 files)"
echo "  ✓ Traffic      (4 files)"
echo "  ✓ ScanEngine   (5 files)"
echo "  ✓ Models       (3 files)"
echo "  ✓ Utilities    (1 file)"
echo "  ✓ Menu         (1 file)"
echo "  ✓ AI Providers (6 files)"
echo ""
echo "AI Providers included:"
echo "  ✓ Ollama (local)"
echo "  ✓ OpenAI"
echo "  ✓ Claude"
echo ""
echo "To install in Burp Suite:"
echo "  1. Open Burp Suite"
echo "  2. Go to Extender → Extensions"
echo "  3. Click 'Add'"
echo "  4. Extension Type: Java"
echo "  5. Select: $OUTPUT_JAR"
echo ""
echo "=========================================="