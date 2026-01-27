package logger

import (
	"os"
	"path/filepath"

	"github.com/fisker/zjump-backend/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Logger 全局日志实例
	Logger *zap.Logger
	// SugaredLogger 带语法糖的日志实例（支持格式化）
	Sugar *zap.SugaredLogger
)

// Init 初始化日志系统
func Init(cfg *config.LoggingConfig) error {
	// 解析日志级别
	level := parseLevel(cfg.Level)

	// 创建编码器配置（美化输出）
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder, // 彩色级别
		EncodeTime:     zapcore.ISO8601TimeEncoder,       // ISO8601 时间格式
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder, // 短文件名
	}

	var cores []zapcore.Core

	// 根据配置决定输出位置
	switch cfg.Output {
	case "console":
		// 仅输出到控制台
		consoleCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			level,
		)
		cores = append(cores, consoleCore)

	case "file":
		// 仅输出到文件（不带颜色）
		fileEncoderConfig := encoderConfig
		fileEncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder // 文件不需要颜色

		fileWriter, err := getFileWriter(cfg.File)
		if err != nil {
			return err
		}

		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(fileEncoderConfig), // 文件用JSON格式
			zapcore.AddSync(fileWriter),
			level,
		)
		cores = append(cores, fileCore)

	case "both":
		// 同时输出到控制台和文件
		// 控制台：彩色、易读格式
		consoleCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			level,
		)
		cores = append(cores, consoleCore)

		// 文件：JSON格式、无颜色
		fileEncoderConfig := encoderConfig
		fileEncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

		fileWriter, err := getFileWriter(cfg.File)
		if err != nil {
			return err
		}

		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(fileEncoderConfig),
			zapcore.AddSync(fileWriter),
			level,
		)
		cores = append(cores, fileCore)

	default:
		// 默认输出到控制台
		consoleCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			level,
		)
		cores = append(cores, consoleCore)
	}

	// 创建 logger
	core := zapcore.NewTee(cores...)
	Logger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	Sugar = Logger.Sugar()

	// 设置为全局 logger
	zap.ReplaceGlobals(Logger)

	Sugar.Infof("✅ Logger initialized: output=%s, level=%s", cfg.Output, cfg.Level)
	return nil
}

// getFileWriter 获取文件写入器
func getFileWriter(logFile string) (*os.File, error) {
	// 确保日志目录存在
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	// 打开或创建日志文件（追加模式）
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// parseLevel 解析日志级别
func parseLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// Debug 调试级别日志
func Debug(msg string, fields ...zap.Field) {
	if Logger != nil {
		Logger.Debug(msg, fields...)
	}
}

// Debugf 格式化调试日志
func Debugf(format string, args ...interface{}) {
	if Sugar != nil {
		Sugar.Debugf(format, args...)
	}
}

// Info 信息级别日志
func Info(msg string, fields ...zap.Field) {
	if Logger != nil {
		Logger.Info(msg, fields...)
	}
}

// Infof 格式化信息日志
func Infof(format string, args ...interface{}) {
	if Sugar != nil {
		Sugar.Infof(format, args...)
	}
}

// Warn 警告级别日志
func Warn(msg string, fields ...zap.Field) {
	if Logger != nil {
		Logger.Warn(msg, fields...)
	}
}

// Warnf 格式化警告日志
func Warnf(format string, args ...interface{}) {
	if Sugar != nil {
		Sugar.Warnf(format, args...)
	}
}

// Error 错误级别日志
func Error(msg string, fields ...zap.Field) {
	if Logger != nil {
		Logger.Error(msg, fields...)
	}
}

// Errorf 格式化错误日志
func Errorf(format string, args ...interface{}) {
	if Sugar != nil {
		Sugar.Errorf(format, args...)
	}
}

// Fatal 致命错误日志（会退出程序）
func Fatal(msg string, fields ...zap.Field) {
	if Logger != nil {
		Logger.Fatal(msg, fields...)
	}
}

// Fatalf 格式化致命错误日志
func Fatalf(format string, args ...interface{}) {
	if Sugar != nil {
		Sugar.Fatalf(format, args...)
	}
}

// Sync 刷新缓冲区
func Sync() {
	if Logger != nil {
		Logger.Sync()
	}
}

// With 创建带字段的子 logger
func With(fields ...zap.Field) *zap.Logger {
	if Logger != nil {
		return Logger.With(fields...)
	}
	return nil
}
