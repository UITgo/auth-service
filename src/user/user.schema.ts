import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User {
  @Prop({ unique: true, required: true }) email: string;
  @Prop() phone?: string;

  @Prop({ default: false }) isDriver: boolean;
  @Prop({ default: false }) isEmailVerified: boolean;

  @Prop({ unique: true, sparse: true }) cognitoSub?: string;

  @Prop() password?: string;
}
export type UserDocument = User & Document;
export const UserSchema = SchemaFactory.createForClass(User);
