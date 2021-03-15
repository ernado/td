package entity

import "github.com/gotd/td/tg"

// Plain formats message as plain text.
func (b *Builder) Plain(s string) *Builder {
	b.message.WriteString(s)
	return b
}

// Mention formats message as Mention message entity.
// See https://core.telegram.org/constructor/messageEntityMention.
func (b *Builder) Mention(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityMention{Offset: offset, Length: limit}
	})
}

// Hashtag formats message as Hashtag message entity.
// See https://core.telegram.org/constructor/messageEntityHashtag.
func (b *Builder) Hashtag(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityHashtag{Offset: offset, Length: limit}
	})
}

// BotCommand formats message as BotCommand message entity.
// See https://core.telegram.org/constructor/messageEntityBotCommand.
func (b *Builder) BotCommand(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityBotCommand{Offset: offset, Length: limit}
	})
}

// URL formats message as Url message entity.
// See https://core.telegram.org/constructor/messageEntityUrl.
func (b *Builder) URL(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityURL{Offset: offset, Length: limit}
	})
}

// Email formats message as Email message entity.
// See https://core.telegram.org/constructor/messageEntityEmail.
func (b *Builder) Email(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityEmail{Offset: offset, Length: limit}
	})
}

// Bold formats message as Bold message entity.
// See https://core.telegram.org/constructor/messageEntityBold.
func (b *Builder) Bold(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityBold{Offset: offset, Length: limit}
	})
}

// Italic formats message as Italic message entity.
// See https://core.telegram.org/constructor/messageEntityItalic.
func (b *Builder) Italic(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityItalic{Offset: offset, Length: limit}
	})
}

// Code formats message as Code message entity.
// See https://core.telegram.org/constructor/messageEntityCode.
func (b *Builder) Code(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityCode{Offset: offset, Length: limit}
	})
}

// Pre formats message as Pre message entity.
// See https://core.telegram.org/constructor/messageEntityPre.
func (b *Builder) Pre(s, lang string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityPre{Offset: offset, Length: limit, Language: lang}
	})
}

// TextURL formats message as TextUrl message entity.
// See https://core.telegram.org/constructor/messageEntityTextUrl.
func (b *Builder) TextURL(s, url string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityTextURL{Offset: offset, Length: limit, URL: url}
	})
}

// MentionName formats message as MentionName message entity.
// See https://core.telegram.org/constructor/messageEntityMentionName.
func (b *Builder) MentionName(s string, userID int) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityMentionName{Offset: offset, Length: limit, UserID: userID}
	})
}

// Phone formats message as Phone message entity.
// See https://core.telegram.org/constructor/messageEntityPhone.
func (b *Builder) Phone(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityPhone{Offset: offset, Length: limit}
	})
}

// Cashtag formats message as Cashtag message entity.
// See https://core.telegram.org/constructor/messageEntityCashtag.
func (b *Builder) Cashtag(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityCashtag{Offset: offset, Length: limit}
	})
}

// Underline formats message as Underline message entity.
// See https://core.telegram.org/constructor/messageEntityUnderline.
func (b *Builder) Underline(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityUnderline{Offset: offset, Length: limit}
	})
}

// Strike formats message as Strike message entity.
// See https://core.telegram.org/constructor/messageEntityStrike.
func (b *Builder) Strike(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityStrike{Offset: offset, Length: limit}
	})
}

// Blockquote formats message as Blockquote message entity.
// See https://core.telegram.org/constructor/messageEntityBlockquote.
func (b *Builder) Blockquote(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityBlockquote{Offset: offset, Length: limit}
	})
}

// BankCard formats message as formats message entity.
// See https://core.telegram.org/constructor/messageEntityBankCard.
func (b *Builder) BankCard(s string) *Builder {
	return b.appendMessage(s, func(offset, limit int) tg.MessageEntityClass {
		return &tg.MessageEntityBankCard{Offset: offset, Length: limit}
	})
}
